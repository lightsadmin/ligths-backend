const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 5001;

app.use(cors());
app.use(express.json());

// Simple test endpoint
app.get("/test", (req, res) => {
  res.json({ message: "Test server working!" });
});

// Stock companies endpoint (isolated)
app.get("/api/stock-companies", async (req, res) => {
  try {
    const { search, exchange = "US", country } = req.query;

    console.log(`Stock companies endpoint hit with exchange: ${exchange}`);

    // Use the same Finnhub API key as other endpoints
    const FINNHUB_API_KEY = "d28seapr01qle9gsj64gd28seapr01qle9gsj650";

    // Define exchange mappings for different countries
    const exchangeMap = {
      // India
      NSE: "NS", // National Stock Exchange of India
      BSE: "BO", // Bombay Stock Exchange
      INDIA: ["NS", "BO"], // Both Indian exchanges

      // USA
      US: "US",
      NASDAQ: "US",
      NYSE: "US",

      // Other countries
      UK: "L", // London Stock Exchange
      HONG_KONG: "HK", // Hong Kong Stock Exchange
      CANADA: "TO", // Toronto Stock Exchange
      GERMANY: "F", // Frankfurt Stock Exchange
      JAPAN: "T", // Tokyo Stock Exchange
      AUSTRALIA: "AX", // Australian Securities Exchange
    };

    // Get exchanges to fetch based on the request
    let exchangesToFetch = [];

    if (country === "INDIA" || exchange === "INDIA") {
      exchangesToFetch = ["NS", "BO"];
    } else if (Array.isArray(exchangeMap[exchange.toUpperCase()])) {
      exchangesToFetch = exchangeMap[exchange.toUpperCase()];
    } else {
      exchangesToFetch = [exchangeMap[exchange.toUpperCase()] || exchange];
    }

    console.log(
      `Fetching stocks from exchanges: ${exchangesToFetch.join(", ")}`
    );

    // For testing, return a simple response
    res.json({
      companies: [
        { symbol: "AAPL", name: "Apple Inc", exchange: "US" },
        { symbol: "MSFT", name: "Microsoft Corp", exchange: "US" },
      ],
      total: 2,
      exchanges: exchangesToFetch,
      requestedExchange: exchange,
    });
  } catch (error) {
    console.error("Error in stock companies endpoint:", error);
    res.status(500).json({
      error: "Failed to fetch stock companies",
      message: error.message,
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🧪 Test server running on port ${PORT}`);
  console.log(`📱 Access at: http://10.69.228.236:${PORT}`);
});
