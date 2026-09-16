# KF8 Copy Deploy

Yeh package existing KF8-3 ko change nahi karta.

## Links after deployment

- User website: `https://rahul-play.onrender.com/`
- Admin website: `https://rahul-play.onrender.com/admin`
- Health check: `https://rahul-play.onrender.com/api/health`

## Required Render environment variables

- `MONGODB_URI`: apne MongoDB cluster ka connection string
- `DB_NAME=rahul_play`: isi se purane KF8-3 ka data alag rahega
- `JWT_SECRET`: kam-se-kam 32 random characters
- `ADMIN_USERNAME`: naya admin username
- `ADMIN_EMAIL`: naya admin email
- `ADMIN_PASSWORD`: strong naya admin password
- `ALLOWED_ORIGINS=https://rahul-play.onrender.com`

## Render settings

- Branch: `kf8-copy`
- Runtime: Node
- Build command: `npm install`
- Start command: `node server.js`
- Plan: Free
- Region: Singapore

GitHub repository me package upload/push hone ke baad hi Render service create karein.
