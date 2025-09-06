const yahooFinance = require("yahoo-finance2").default;
const fs = require("fs");
const path = require("path");
const cron = require("node-cron");

// Stock Model (you'll need to import this from your models)
let Stock = null;

// Function to set the Stock model from outside
const setStockModel = (stockModel) => {
  Stock = stockModel;
};

/**
 * Format company name for display
 */
const formatCompanyNameStock = (symbol) => {
  const nameMap = {
    RELIANCE: "Reliance Industries",
    TCS: "Tata Consultancy Services",
    HDFCBANK: "HDFC Bank",
    ICICIBANK: "ICICI Bank",
    HINDUNILVR: "Hindustan Unilever",
    INFY: "Infosys",
    ITC: "ITC Limited",
    SBIN: "State Bank of India",
    BHARTIARTL: "Bharti Airtel",
    KOTAKBANK: "Kotak Mahindra Bank",
    LT: "Larsen & Toubro",
    BAJFINANCE: "Bajaj Finance",
    ASIANPAINT: "Asian Paints",
    MARUTI: "Maruti Suzuki India",
    HCLTECH: "HCL Technologies",
    AXISBANK: "Axis Bank",
    WIPRO: "Wipro",
    ONGC: "Oil & Natural Gas Corporation",
    TECHM: "Tech Mahindra",
    TITAN: "Titan Company",
    NESTLEIND: "Nestle India",
    POWERGRID: "Power Grid Corporation",
    NTPC: "NTPC Limited",
    ULTRACEMCO: "UltraTech Cement",
    JSWSTEEL: "JSW Steel",
    SUNPHARMA: "Sun Pharmaceutical",
    BAJAJFINSV: "Bajaj Finserv",
    DRREDDY: "Dr. Reddy's Laboratories",
    TATAMOTORS: "Tata Motors",
    CIPLA: "Cipla",
    EICHERMOT: "Eicher Motors",
    GRASIM: "Grasim Industries",
    HEROMOTOCO: "Hero MotoCorp",
    COALINDIA: "Coal India",
    BPCL: "Bharat Petroleum",
    TATASTEEL: "Tata Steel",
    BRITANNIA: "Britannia Industries",
    DIVISLAB: "Divi's Laboratories",
    ADANIPORTS: "Adani Ports",
    SHREECEM: "Shree Cement",
    VEDL: "Vedanta Limited",
    APOLLOHOSP: "Apollo Hospitals",
    HINDALCO: "Hindalco Industries",
    INDUSINDBK: "IndusInd Bank",
    UPL: "UPL Limited",
    TATACONSUM: "Tata Consumer Products",
    ADANIENT: "Adani Enterprises",
    GODREJCP: "Godrej Consumer Products",
    SBILIFE: "SBI Life Insurance",
    PIDILITIND: "Pidilite Industries",
    HDFCLIFE: "HDFC Life Insurance",
  };

  return nameMap[symbol] || symbol;
};

/**
 * Get sector information from symbol (basic implementation)
 */
const getSectorFromSymbol = (symbol) => {
  const sectorMap = {
    RELIANCE: "Oil & Gas",
    TCS: "IT Services",
    HDFCBANK: "Banking",
    ICICIBANK: "Banking",
    HINDUNILVR: "FMCG",
    INFY: "IT Services",
    ITC: "FMCG",
    SBIN: "Banking",
    BHARTIARTL: "Telecom",
    KOTAKBANK: "Banking",
    LT: "Engineering",
    BAJFINANCE: "Financial Services",
    ASIANPAINT: "Paints",
    MARUTI: "Automobile",
    HCLTECH: "IT Services",
    AXISBANK: "Banking",
    WIPRO: "IT Services",
    ONGC: "Oil & Gas",
    TECHM: "IT Services",
    TITAN: "Jewelry",
    NESTLEIND: "FMCG",
    POWERGRID: "Power",
    NTPC: "Power",
    ULTRACEMCO: "Cement",
    JSWSTEEL: "Steel",
    SUNPHARMA: "Pharmaceuticals",
    BAJAJFINSV: "Financial Services",
    DRREDDY: "Pharmaceuticals",
    TATAMOTORS: "Automobile",
    CIPLA: "Pharmaceuticals",
    EICHERMOT: "Automobile",
    GRASIM: "Cement",
    HEROMOTOCO: "Automobile",
    COALINDIA: "Mining",
    BPCL: "Oil & Gas",
    TATASTEEL: "Steel",
    BRITANNIA: "FMCG",
    DIVISLAB: "Pharmaceuticals",
    ADANIPORTS: "Infrastructure",
    SHREECEM: "Cement",
    VEDL: "Mining",
    APOLLOHOSP: "Healthcare",
    HINDALCO: "Metals",
    INDUSINDBK: "Banking",
    UPL: "Chemicals",
    TATACONSUM: "FMCG",
    ADANIENT: "Infrastructure",
    GODREJCP: "FMCG",
    SBILIFE: "Insurance",
    PIDILITIND: "Chemicals",
    HDFCLIFE: "Insurance",
  };

  return sectorMap[symbol] || "Others";
};

const loadSymbolsFromCSVStock = () => {
  try {
    const csvPath = path.join(__dirname, "Copy of Book1 (1)(2).csv");
    const csvData = fs.readFileSync(csvPath, "utf8");
    const lines = csvData.split("\n");

    const symbols = [];
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line) {
        const parts = line.split(",");
        if (parts.length >= 2) {
          const symbol = parts[0].trim();
          symbols.push({
            symbol: `${symbol}.NS`,
            baseSymbol: symbol,
            exchange: "NSE",
          });
        }
      }
    }

    console.log(`📈 Loaded ${symbols.length} symbols from CSV`);
    return symbols;
  } catch (error) {
    console.error("❌ Error loading symbols from CSV:", error);
    return [];
  }
};

async function fetchQuoteStock(symbolObj) {
  try {
    console.log(`🔄 Fetching quote for ${symbolObj.symbol}...`);
    const quote = await yahooFinance.quote(symbolObj.symbol);

    return {
      symbol: quote.symbol,
      name: quote.shortName || formatCompanyNameStock(symbolObj.baseSymbol),
      exchange: symbolObj.exchange,
      currency: quote.currency || "INR",
      country: "India",
      type: "Common Stock",
      sector: quote.sector || getSectorFromSymbol(symbolObj.baseSymbol),
      currentPrice: quote.regularMarketPrice,
      dayChange: quote.regularMarketChange,
      dayChangePercent: quote.regularMarketChangePercent,
      volume: quote.regularMarketVolume,
      marketCap: quote.marketCap,
      lastUpdated: new Date(),
    };
  } catch (err) {
    console.error(`❌ Failed to fetch ${symbolObj.symbol}:`, err.message);
    return null; // Return null on error so it's not added to the list
  }
}

const allStockSymbols = loadSymbolsFromCSVStock();

const updateAllStocksDaily = async () => {
  if (!Stock) {
    console.error("❌ Stock model not set. Cannot update stocks.");
    return;
  }

  try {
    console.log("📈 Initiating daily stock data update...");
    const symbolsToUpdate = allStockSymbols.map((s) => ({
      symbol: s.symbol,
      baseSymbol: s.baseSymbol,
      exchange: s.exchange,
    }));

    console.log(
      `📊 Processing ${symbolsToUpdate.length} stocks in background...`
    );

    // Process stocks in smaller batches to avoid blocking the main thread
    const batchSize = 10;
    let processedCount = 0;

    const processBatch = async (batch) => {
      const updates = [];

      for (const symbolObj of batch) {
        try {
          const quote = await fetchQuoteStock(symbolObj);
          if (quote) {
            updates.push({
              updateOne: {
                filter: { symbol: quote.symbol },
                update: {
                  $set: {
                    symbol: quote.symbol,
                    name: quote.name,
                    exchange: quote.exchange,
                    currentPrice: quote.currentPrice,
                    dayChange: quote.dayChange,
                    dayChangePercent: quote.dayChangePercent,
                    volume: quote.volume,
                    marketCap: quote.marketCap,
                    lastUpdated: quote.lastUpdated,
                  },
                },
                upsert: true,
              },
            });
          }
        } catch (error) {
          console.error(
            `❌ Error processing ${symbolObj.symbol}:`,
            error.message
          );
        }
      }

      if (updates.length > 0) {
        try {
          const result = await Stock.bulkWrite(updates, { ordered: false });
          processedCount += updates.length;
          console.log(
            `💾 Batch update complete. Processed: ${processedCount}/${symbolsToUpdate.length} stocks (Inserted: ${result.upsertedCount}, Modified: ${result.modifiedCount})`
          );
        } catch (error) {
          console.error("❌ Error during batch update:", error);
        }
      }
    };

    // Process all batches without blocking the main thread
    const processBatchesAsync = async () => {
      for (let i = 0; i < symbolsToUpdate.length; i += batchSize) {
        const batch = symbolsToUpdate.slice(i, i + batchSize);
        await processBatch(batch);

        // Add a small delay between batches to avoid overwhelming Yahoo Finance API
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      console.log(
        `✅ Daily stock data update completed. Total processed: ${processedCount} stocks`
      );
    };

    // Start processing batches asynchronously (non-blocking)
    processBatchesAsync().catch((error) => {
      console.error("❌ Error during async stock update:", error);
    });

    // Return immediately without blocking
    console.log("📈 Stock update process started in background");
  } catch (error) {
    console.error("❌ Error during daily stock update:", error);
  }
};

// Function to setup cron job and initial update
const initializeStockService = () => {
  // Schedule daily stock data update at 3:00 PM India Time
  cron.schedule("0 15 * * *", updateAllStocksDaily, {
    timezone: "Asia/Kolkata",
  });

  // Start stock update after server is fully started (delay to avoid blocking)
  console.log("📈 Stock data update will start in 10 seconds...");
  setTimeout(() => {
    console.log("📈 Starting background stock data update...");
    updateAllStocksDaily().catch((error) => {
      console.error("❌ Error in background stock update:", error);
    });
  }, 10000); // 10 second delay
};

// Stock API routes
const setupStockRoutes = (app) => {
  // NEW: Endpoint to get ALL daily-updated stocks without pagination
  app.get("/api/all-stocks", async (req, res) => {
    if (!Stock) {
      return res.status(500).json({ error: "Stock model not initialized" });
    }

    try {
      const { search } = req.query;

      let query = {};
      if (search) {
        query = {
          $or: [
            { symbol: { $regex: search, $options: "i" } },
            { name: { $regex: search, $options: "i" } },
          ],
        };
      }

      const stocks = await Stock.find(query).sort({ name: 1 });

      // If no stocks in database, return basic symbol info
      if (stocks.length === 0 && allStockSymbols.length > 0) {
        console.log(
          "📊 No stocks in database yet, returning basic symbol data"
        );
        const basicStocks = allStockSymbols.slice(0, 100).map((s) => ({
          symbol: s.symbol,
          name: s.baseSymbol,
          exchange: s.exchange,
          price: 0,
          change: 0,
          changePercent: 0,
          volume: 0,
          marketCap: 0,
          lastUpdated: new Date(),
        }));

        return res.json({
          stocks: basicStocks,
          totalStocks: basicStocks.length,
          note: "Stock data is being updated in background. Real data will be available shortly.",
        });
      }

      res.json({
        stocks: stocks,
        totalStocks: stocks.length,
      });
    } catch (error) {
      console.error("❌ Error fetching all stocks:", error);
      res.status(500).json({ error: "Failed to fetch all stocks" });
    }
  });

  // NEW: Endpoint to get daily-updated stocks from the database
  app.get("/api/daily-stocks", async (req, res) => {
    if (!Stock) {
      return res.status(500).json({ error: "Stock model not initialized" });
    }

    try {
      const { page = 1, limit = 5000, search } = req.query;
      const pageNum = parseInt(page);
      const pageLimit = parseInt(limit);

      let query = {};
      if (search) {
        query = {
          $or: [
            { symbol: { $regex: search, $options: "i" } },
            { name: { $regex: search, $options: "i" } },
          ],
        };
      }

      const totalCount = await Stock.countDocuments(query);
      const stocks = await Stock.find(query)
        .sort({ name: 1 })
        .skip((pageNum - 1) * pageLimit)
        .limit(pageLimit);

      res.json({
        stocks,
        pagination: {
          currentPage: pageNum,
          totalStocks: totalCount,
          totalPages: Math.ceil(totalCount / pageLimit),
          hasMore: pageNum * pageLimit < totalCount,
        },
      });
    } catch (error) {
      console.error("❌ Error fetching daily stocks:", error);
      res.status(500).json({ error: "Failed to fetch daily stocks" });
    }
  });

  // API: Get single stock detail
  app.get("/api/stocks/:symbol", async (req, res) => {
    try {
      const { symbol } = req.params;
      console.log(`📊 Fetching detailed quote for ${symbol}`);

      const symbolObj = {
        symbol: symbol.includes(".") ? symbol : `${symbol}.NS`,
        baseSymbol: symbol.replace(".NS", "").replace(".BO", ""),
        exchange: symbol.includes(".BO") ? "BSE" : "NSE",
      };

      const quote = await fetchQuoteStock(symbolObj);
      if (!quote) {
        return res.status(404).json({ error: "Stock not found" });
      }

      res.json(quote);
    } catch (error) {
      console.error(
        `❌ Error fetching stock detail for ${req.params.symbol}:`,
        error
      );
      res.status(500).json({ error: "Failed to fetch stock detail" });
    }
  });

  console.log("📈 Yahoo Finance stock endpoints integrated successfully");
};

module.exports = {
  setStockModel,
  initializeStockService,
  setupStockRoutes,
  fetchQuoteStock,
  getSectorFromSymbol,
  loadSymbolsFromCSVStock,
  updateAllStocksDaily,
  formatCompanyNameStock,
};
