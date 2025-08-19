const yahooFinance = require("yahoo-finance2").default;

// Test yfinance functionality
async function testYahooFinance() {
  try {
    console.log("Testing Yahoo Finance...");

    // Test Indian stock
    const indianStock = await yahooFinance.quote("RELIANCE.NS");
    console.log("Indian Stock (Reliance):", {
      symbol: "RELIANCE.NS",
      name: indianStock.longName || indianStock.shortName,
      price: indianStock.regularMarketPrice,
      currency: "INR",
    });

    // Test US stock
    const usStock = await yahooFinance.quote("AAPL");
    console.log("US Stock (Apple):", {
      symbol: "AAPL",
      name: usStock.longName || usStock.shortName,
      price: usStock.regularMarketPrice,
      currency: "USD",
    });
  } catch (error) {
    console.error("Error testing Yahoo Finance:", error.message);
  }
}

testYahooFinance();
