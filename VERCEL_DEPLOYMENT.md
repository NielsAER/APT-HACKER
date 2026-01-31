# XPOSE APT AI v8.0 - Vercel Deployment Guide

## Quick Deploy

### Option 1: Deploy from GitHub

1. Push this code to a GitHub repository
2. Go to [vercel.com](https://vercel.com) and sign in
3. Click "Add New Project"
4. Import your GitHub repository
5. Configure environment variables (see below)
6. Click "Deploy"

### Option 2: Deploy with Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy
cd APTAI-main
vercel

# For production deployment
vercel --prod
```

## Required Environment Variables

Set these in your Vercel project settings (Settings → Environment Variables):

### Required (at least one LLM):
```
LLM_PROVIDER=deepseek
LLM_API_KEY=your_deepseek_api_key
```

Alternative LLM providers:
```
# For Groq (free, fast)
LLM_PROVIDER=groq
LLM_API_KEY=your_groq_api_key

# For OpenAI
LLM_PROVIDER=openai
LLM_API_KEY=your_openai_api_key
```

### Optional (enhanced features):
```
SHODAN_API_KEY=your_shodan_key          # For exposed services scanning
DEHASHED_EMAIL=your_email               # For breach data
DEHASHED_API_KEY=your_dehashed_key      # For breach data
HUNTER_API_KEY=your_hunter_key          # For email discovery
```

### Database (Recommended for Production):
```
# For persistent data, use Neon Postgres (free tier available)
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

Without DATABASE_URL, the app uses SQLite in /tmp which resets between deployments.

## Get API Keys

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| DeepSeek | Yes ($0 credit) | [platform.deepseek.com](https://platform.deepseek.com) |
| Groq | Yes (free) | [console.groq.com](https://console.groq.com) |
| Shodan | Limited | [shodan.io](https://shodan.io) |
| Hunter.io | 25 req/mo | [hunter.io](https://hunter.io) |
| DeHashed | Paid | [dehashed.com](https://dehashed.com) |
| Neon (Postgres) | Yes | [neon.tech](https://neon.tech) |

## Post-Deployment

1. Visit your Vercel URL (e.g., `https://your-app.vercel.app`)
2. Check the status at `/api/status`
3. Create a new APT project and test OSINT

## Troubleshooting

### "LLM not configured" error
- Make sure `LLM_API_KEY` is set in Vercel environment variables
- Redeploy after adding environment variables

### Database resets
- Use Neon Postgres for persistent storage
- Add `DATABASE_URL` environment variable

### Timeout errors
- Vercel serverless has 60 second limit
- Large OSINT scans may timeout
- Consider using Groq (faster) or increasing timeout in vercel.json

### Build failures
- Check Python version (should be 3.11)
- Verify requirements.txt has no version conflicts

## Architecture Notes

- **Serverless**: Each request runs as a separate function
- **No streaming**: SSE is disabled on Vercel (use sync responses)
- **Cold starts**: First request may be slow (~2-3 seconds)
- **Memory**: 1024MB allocated per function
- **Timeout**: 60 seconds max per request

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file
echo "LLM_PROVIDER=deepseek" > .env
echo "LLM_API_KEY=your_key" >> .env

# Run locally
python main.py
```

Visit `http://localhost:8080`

## Support

For issues, check:
1. Vercel deployment logs
2. Function logs in Vercel dashboard
3. Browser console for frontend errors
