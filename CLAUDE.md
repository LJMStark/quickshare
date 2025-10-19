# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an HTML code sharing tool built with Express.js that allows users to create, share and view HTML code snippets with optional password protection and session management.

## Key Development Commands

### Development
```bash
npm run dev              # Start development server with nodemon (port 5678)
npm start               # Start production server (port 8888)
npm run test            # Start test server (port 3000)
```

### Environment Setup
Create `.env` file with:
```env
NODE_ENV=development
PORT=5678
AUTH_ENABLED=true
AUTH_PASSWORD=your_password_here
DB_PATH=./db/database.sqlite
```

## Architecture & Core Components

### Application Structure
- **Entry Point**: `app.js` - Main Express application with middleware setup and routing
- **Configuration**: `config.js` - Environment-based configuration management
- **Database**: SQLite3 with auto-initialization (`models/db.js`, `models/pages.js`)
- **Authentication**: Session-based auth with file storage and cookie fallback (`middleware/auth.js`)
- **Content Processing**: Multi-format content rendering supporting HTML, Markdown, SVG, and Mermaid diagrams

### Key Architectural Patterns

1. **Dual Authentication System**: Uses both Express sessions and cookies for reliability
2. **Content Type Detection**: Automatic detection of HTML, Markdown, Mermaid, and SVG content
3. **Code Block Extraction**: Can extract and render code blocks from multi-code content
4. **Password Protection**: Optional per-page password protection with 5-digit numeric passwords

### Database Schema
```sql
CREATE TABLE pages (
  id TEXT PRIMARY KEY,          -- 7-character hash ID
  html_content TEXT NOT NULL,   -- Content storage
  created_at INTEGER NOT NULL,  -- Unix timestamp
  password TEXT,                -- 5-digit protection password
  is_protected INTEGER DEFAULT 0, -- Boolean flag
  code_type TEXT DEFAULT 'html'  -- Detected content type
);
```

### Authentication Flow
- Login required only for creating pages (`/`, `/api/pages/create`)
- Shared pages accessible without login (`/view/:id`)
- Session stored in `./sessions/` directory with file-based storage
- Dual authentication: session + cookie for reliability

### Content Rendering Pipeline
1. Content type detection in `utils/codeDetector.js`
2. Code block extraction for multi-format content
3. Context-aware rendering in `utils/contentRenderer.js`
4. Proper HTML wrapping for non-HTML content types

## Important File Locations

- **Main app**: `app.js` - All middleware and route setup
- **Routes**: `routes/pages.js` - API endpoints for page operations
- **Models**: `models/pages.js`, `models/db.js` - Database operations
- **Middleware**: `middleware/auth.js` - Authentication logic
- **Utils**: `utils/codeDetector.js`, `utils/contentRenderer.js` - Content processing
- **Views**: `views/` - EJS templates for web interface
- **Database**: `db/html-go.db` - SQLite database file

## Development Notes

### Content Type Support
The system automatically detects and renders:
- HTML documents (with DOCTYPE detection)
- Markdown (using `marked` library)
- Mermaid diagrams (with `mermaid` rendering)
- SVG content (direct display)
- Multi-code blocks (combined HTML output)

### Security Considerations
- Password protection uses 5-digit numeric passwords
- Session file storage with 24-hour TTL
- Input validation and sanitization
- CORS enabled for cross-origin requests

### Port Configuration
- Development: 5678 (configurable via PORT env var)
- Production: 8888 (hardcoded for deployment)
- Test: 3000 (configurable)

### Debugging Features
- Comprehensive console logging throughout the application
- Session and authentication state logging
- Content type detection debugging
- Database operation logging