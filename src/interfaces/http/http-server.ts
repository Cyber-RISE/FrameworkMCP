#!/usr/bin/env node

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { SafeguardManager } from '../../core/safeguard-manager.js';
import { RateLimitConfig, RateLimitErrorResponse } from '../../shared/types.js';

interface ErrorResponse {
  error: string;
  details?: string;
  timestamp: string;
}

export class FrameworkHttpServer {
  private app: express.Application;
  private safeguardManager: SafeguardManager;
  private port: number;
  private rateLimitConfig: RateLimitConfig;

  constructor(port: number = 8080) {
    this.app = express();
    this.safeguardManager = new SafeguardManager();
    this.port = port;
    this.rateLimitConfig = this.parseRateLimitConfig();

    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  private parseRateLimitConfig(): RateLimitConfig {
    const skipIpsEnv = process.env.RATE_LIMIT_SKIP_IPS;
    return {
      // 20 per 10s, mirroring the RATE_LIMITER binding in wrangler.jsonc.
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '10000', 10),
      max: parseInt(process.env.RATE_LIMIT_MAX || '20', 10),
      skipIps: skipIpsEnv ? skipIpsEnv.split(',').map(ip => ip.trim()) : undefined
    };
  }

  /**
   * Resolve Express's `trust proxy` setting from TRUST_PROXY.
   *
   * Left unset, `req.ip` is the socket peer. Behind a load balancer that is the
   * balancer's address, so every client on earth shares one rate-limit bucket
   * and RATE_LIMIT_SKIP_IPS can never match a real client. Set it to the number
   * of proxy hops in front of this server (usually 1) to recover the true IP.
   *
   * Accepts a hop count, or any address list Express understands
   * ('loopback', '10.0.0.0/8', a comma-separated mix). Returns false when
   * unset, which keeps the direct-connection default.
   */
  private parseTrustProxy(): number | string | boolean {
    const raw = process.env.TRUST_PROXY?.trim();
    if (!raw) {
      return false;
    }

    // 'true' and '*' trust whatever X-Forwarded-For the client sends, making
    // req.ip attacker-controlled -- that bypasses rate limiting outright and
    // lets anyone forge their way into the RATE_LIMIT_SKIP_IPS allowlist.
    // express-rate-limit also refuses to run against a permissive setting
    // (ERR_ERL_PERMISSIVE_TRUST_PROXY), so reject it here with a usable message
    // rather than letting it fail deeper in the stack.
    if (raw === 'true' || raw === '*') {
      throw new Error(
        'TRUST_PROXY=true trusts any client-supplied X-Forwarded-For, which ' +
        'defeats rate limiting. Set it to the number of proxy hops in front ' +
        'of this server (e.g. TRUST_PROXY=1) or to specific addresses/CIDRs.'
      );
    }

    if (raw === 'false') {
      return false;
    }

    return /^[0-9]+$/.test(raw) ? parseInt(raw, 10) : raw;
  }

  private setupMiddleware(): void {
    // Must precede the rate limiter, which resolves req.ip through this setting.
    this.app.set('trust proxy', this.parseTrustProxy());

    // Rate limiting middleware - must be before other middleware
    const limiter = rateLimit({
      windowMs: this.rateLimitConfig.windowMs,
      max: this.rateLimitConfig.max,
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        if (this.rateLimitConfig.skipIps && req.ip) {
          return this.rateLimitConfig.skipIps.includes(req.ip);
        }
        return false;
      },
      message: {
        error: 'Too many requests',
        retryAfter: 'See Retry-After header',
        timestamp: new Date().toISOString()
      },
      handler: (req, res, _next, options) => {
        console.log(`[Rate Limit] IP ${req.ip} exceeded limit`);
        res.status(429).json(options.message);
      }
    });

    this.app.use(limiter);

    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration. `cors` matches array entries by exact string equality,
    // so a literal '*' inside an array blocks every cross-origin request instead
    // of allowing any -- the wildcard has to be passed as a bare string to emit
    // `Access-Control-Allow-Origin: *`. Mirrors corsHeaders() in the Worker.
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim())
      || ['http://localhost:3000'];

    // No `credentials: true`: this API is unauthenticated public data, and
    // allowing credentials alongside a wildcard origin is both invalid per spec
    // and the groundwork for a CORS bypass if auth is ever added.
    this.app.use(cors({
      origin: allowedOrigins.includes('*') ? '*' : allowedOrigins,
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // Compression. No body parsers: every route is a GET and none reads a
    // request body, so parsing one only bought attack surface -- 10MB of JSON
    // was parsed even on POSTs to nonexistent paths that end at the 404 handler.
    this.app.use(compression());

    // Request logging in production
    if (process.env.NODE_ENV === 'production') {
      this.app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
        next();
      });
    }
  }

  private setupRoutes(): void {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        uptime: Math.round(process.uptime()),
        version: '3.1.0',
        timestamp: new Date().toISOString()
      });
    });

    // Safeguards health check endpoint - validates data completeness
    this.app.get('/api/health/safeguards', (req, res) => {
      try {
        const allSafeguards = this.safeguardManager.getAllSafeguards();
        const safeguardIds = Object.keys(allSafeguards);

        const totalValidated = safeguardIds.length;

        res.json({
          status: 'healthy',
          safeguards: {
            total: totalValidated,
            expected: 153,
            complete: totalValidated === 153
          },
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        res.status(500).json({
          status: 'error',
          message: 'Failed to validate safeguards data',
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        });
      }
    });



    // Get safeguard details endpoint
    this.app.get('/api/safeguards/:safeguardId', (req, res) => {
      try {
        const { safeguardId } = req.params;
        const includeExamples = req.query.include_examples === 'true';

        this.safeguardManager.validateSafeguardId(safeguardId);

        const safeguard = this.safeguardManager.getSafeguardDetails(safeguardId, includeExamples);
        if (!safeguard) {
          return res.status(404).json(this.createErrorResponse('Safeguard not found'));
        }

        res.json(safeguard);
      } catch (error) {
        console.error('[HTTP Server] get-safeguard-details error:', error);
        res.status(400).json(this.createErrorResponse(error instanceof Error ? error.message : 'Unknown error'));
      }
    });

    // List all safeguards endpoint
    this.app.get('/api/safeguards', (req, res) => {
      try {
        const safeguards = this.safeguardManager.listAvailableSafeguards();
        
        res.json({
          safeguards,
          total: safeguards.length,
          framework: 'CIS Controls v8.1',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        console.error('[HTTP Server] list-safeguards error:', error);
        res.status(500).json(this.createErrorResponse('Internal server error'));
      }
    });


    // API documentation endpoint
    this.app.get('/api', (req, res) => {
      res.json({
        name: 'Framework MCP HTTP API',
        version: '3.1.0',
        description: 'Pure Data Provider serving authentic CIS Controls Framework data',
        endpoints: {
          'GET /api/safeguards': 'List all available CIS safeguards',
          'GET /api/safeguards/:id': 'Get detailed safeguard breakdown',
          'GET /health': 'Health check endpoint',
          'GET /api': 'This documentation'
        },
        framework: 'CIS Controls v8.1 (153 safeguards)',
        deployment: 'Cloud-compatible HTTP API'
      });
    });

    // Root endpoint redirect
    this.app.get('/', (req, res) => {
      res.redirect('/api');
    });
  }

  private setupErrorHandling(): void {
    // 404 handler. Express 5 runs path-to-regexp v8, where a bare '*' is not a
    // valid path -- the wildcard must be named ('/{*splat}').
    this.app.use('/{*splat}', (req, res) => {
      res.status(404).json(this.createErrorResponse(
        `Endpoint not found: ${req.method} ${req.originalUrl}`,
        'Use GET /api for available endpoints'
      ));
    });

    // Global error handler
    this.app.use((error: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
      console.error('[HTTP Server] Unhandled error:', error);
      
      if (!res.headersSent) {
        res.status(500).json(this.createErrorResponse(
          'Internal server error',
          process.env.NODE_ENV === 'development' ? error.message : undefined
        ));
      }
    });
  }

  private createErrorResponse(error: string, details?: string): ErrorResponse {
    return {
      error,
      details,
      timestamp: new Date().toISOString()
    };
  }

  public start(): void {
    this.app.listen(this.port, '0.0.0.0', () => {
      console.log(`🚀 Framework MCP HTTP Server v3.1.0 running on port ${this.port}`);
      console.log(`📊 Health check: http://localhost:${this.port}/health`);
      console.log(`📖 API docs: http://localhost:${this.port}/api`);
      console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`📊 Pure Data Provider - CIS Controls v8.1`);
    });

    // Graceful shutdown handling
    process.on('SIGTERM', () => {
      console.log('🔄 Received SIGTERM, shutting down gracefully...');
      process.exit(0);
    });

    process.on('SIGINT', () => {
      console.log('🔄 Received SIGINT, shutting down gracefully...');
      process.exit(0);
    });
  }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '8080', 10);
  const server = new FrameworkHttpServer(port);
  server.start();
}