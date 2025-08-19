const axios = require("axios");

async function testStockAPI() {
  try {
    console.log("Testing stock companies endpoint...");

    // Test Indian stocks
    const response = await axios.get(
      "http://localhost:5000/api/stock-companies?exchange=INDIA&limit=5"
    );
    console.log("✅ Stock companies response:");
    console.log("Total companies:", response.data.total);
    console.log("Companies returned:", response.data.companies.length);

    if (response.data.companies.length > 0) {
      console.log("First company:", response.data.companies[0]);
    }

    // Test stock quote
    console.log("\nTesting stock quote endpoint...");
    const quoteResponse = await axios.get(
      "http://localhost:5000/api/stock-quote/RELIANCE.NS"
    );
    console.log("✅ Stock quote response:");
    console.log("Symbol:", quoteResponse.data.symbol);
    console.log("Name:", quoteResponse.data.longName);
    console.log("Price:", quoteResponse.data.regularMarketPrice);
    console.log("Currency:", quoteResponse.data.currency);
  } catch (error) {
    console.error("❌ Error testing API:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response data:", error.response.data);
    }
  }
}

testStockAPI();
