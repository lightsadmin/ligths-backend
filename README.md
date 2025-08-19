# LightsOn Backend API

A comprehensive Node.js/Express backend for the LightsOn financial management application.

## 🚀 Features

- **Authentication & Authorization**: JWT-based user authentication
- **Mutual Fund Management**: Live NAV data fetching from AMFI, fund search and filtering
- **Stock Market Integration**: Live stock data via Yahoo Finance RapidAPI
- **Investment Tracking**: CRUD operations for MF and stock investments
- **Goal Management**: Financial goal setting and tracking
- **Portfolio Analytics**: Investment performance analysis
- **Real-time Data**: Automated NAV updates via cron jobs

## 🛠 Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB Atlas
- **Authentication**: JWT (jsonwebtoken)
- **External APIs**: AMFI NAV Data, Yahoo Finance RapidAPI
- **Deployment**: Render.com

## 📦 Installation

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Start development server
npm start
```

## 🔧 Environment Variables

```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
RAPIDAPI_KEY=your_yahoo_finance_rapidapi_key
PORT=5000
```

## 🏗 Project Structure

```
Ligths/
├── server.js              # Main server file
├── package.json           # Dependencies and scripts
├── .env                   # Environment variables
├── render.yaml            # Deployment configuration
└── README.md              # This file
```

## 🔗 API Endpoints

### Authentication

- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/forgot-password` - Password reset

### Mutual Funds

- `GET /mutualfunds/companies` - Get MF companies (grouped)
- `GET /mutualfunds` - Get paginated MF list
- `GET /mutualfunds/:schemeCode` - Get specific MF details
- `POST /update-nav` - Trigger manual NAV update

### Stock Market

- `GET /api/stock-companies` - Get stock companies (RapidAPI)
- `GET /api/stock-quote/:symbol` - Get stock quote
- `GET /api/stock-quotes` - Get multiple stock quotes

### Investments

- `GET /api/mf-investments` - Get user MF investments
- `POST /api/mf-investment` - Create MF investment
- `PUT /api/mf-investment/:id` - Update MF investment
- `DELETE /api/mf-investment/:id` - Delete MF investment

### Goals

- `GET /goals/:username` - Get user goals
- `POST /goals/:username` - Create goal
- `PUT /goals/:username/:id` - Update goal
- `DELETE /goals/:username/:id` - Delete goal

## 🐛 Common Errors & Solutions

### 1. **Duplicate axios Declaration**

**Error**: `SyntaxError: Identifier 'axios' has already been declared`
**Solution**: Removed duplicate `const axios = require("axios");` declaration in stock companies endpoint

### 2. **MongoDB Connection Error**

**Error**: `MongooseError: The 'uri' parameter to 'openUri()' must be a string`
**Solution**: Ensure `MONGODB_URI` environment variable is properly set in `.env` file

### 3. **Port Already in Use**

**Error**: `EADDRINUSE: address already in use 0.0.0.0:5000`
**Solution**:

```bash
# Find and kill process using port 5000
netstat -ano | findstr :5000
taskkill /F /PID <process_id>
```

### 4. **JWT Authentication Issues**

**Error**: `401 Unauthorized` responses
**Solution**:

- Verify JWT_SECRET is set correctly
- Check token format in Authorization header: `Bearer <token>`
- Ensure token hasn't expired

### 5. **MF Data Validation Issues**

**Error**: Only 13,595 funds displayed instead of 17,145
**Solution**: Made validation more lenient:

- Reduced minimum field requirements from 6 to 2
- Accept funds with missing NAV values
- Allow automatic scheme code generation

### 6. **RapidAPI Stock Data**

**Error**: Static stock data not working
**Solution**: Replaced static logic with live Yahoo Finance RapidAPI integration:

```javascript
// OLD: Static data
const companies = staticStockData;

// NEW: Live RapidAPI data
const response = await axios.request({
  method: "GET",
  url: "https://yahoo-finance15.p.rapidapi.com/api/yahoo/co/collections/list_of_lists",
  headers: {
    "X-RapidAPI-Key": process.env.RAPIDAPI_KEY,
    "X-RapidAPI-Host": "yahoo-finance15.p.rapidapi.com",
  },
});
```

### 7. **CORS Issues**

**Error**: Cross-origin requests blocked
**Solution**: Added CORS middleware:

```javascript
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  next();
});
```

### 8. **NAV Data Fetching Timeout**

**Error**: `Operation 'mutualfunds.bulkWrite()' buffering timed out`
**Solution**:

- Increased axios timeout to 60 seconds
- Implemented batch processing for large datasets
- Added connection retry logic

## 🔄 Deployment

### Render.com Deployment

1. Connect GitHub repository
2. Set environment variables in Render dashboard
3. Deploy using `render.yaml` configuration

### Manual Deployment

```bash
# Build for production (if applicable)
npm run build

# Start production server
npm start
```

## 📊 Monitoring

### Health Check

- `GET /test` - Server health check endpoint

### Database Statistics

- `GET /mf-stats` - MF database statistics
- `GET /test-nav-parsing` - Test NAV parsing without DB update

## 🔒 Security Features

- JWT token validation
- Password hashing with bcrypt
- Input validation and sanitization
- Rate limiting (can be added)
- HTTPS in production

## 🚀 Performance Optimizations

- MongoDB indexing on frequently queried fields
- Bulk operations for large datasets
- Cron job for automated NAV updates
- Connection pooling
- Response caching (can be added)

## 📝 Development Notes

- Use `nodemon` for development with auto-restart
- Keep `.env` file secure and never commit to version control
- Regular NAV updates scheduled at 9:15 PM daily
- Monitor MongoDB Atlas usage and scaling

---

**Last Updated**: August 19, 2025
**Version**: 1.0.0
