// Simple test to verify companies endpoint
const axios = require("axios");

async function testCompaniesEndpoint() {
  try {
    console.log("🔍 Testing companies endpoint...");
    const response = await axios.get(
      "http://localhost:5000/mutualfunds/companies"
    );

    console.log(
      `✅ Endpoint working! Received ${response.data.length} companies`
    );

    // Check first few companies
    const firstCompanies = response.data.slice(0, 3);
    firstCompanies.forEach((company, index) => {
      console.log(`\n📋 Company ${index + 1}: ${company.companyName}`);
      console.log(
        `   Schemes: ${company.schemes ? company.schemes.length : 0}`
      );
      if (company.schemes && company.schemes.length > 0) {
        console.log(`   Sample scheme: ${company.schemes[0].schemeName}`);
        console.log(`   NAV: ₹${company.schemes[0].nav}`);
      }
    });

    // Check for invalid schemes
    let invalidSchemes = 0;
    response.data.forEach((company) => {
      if (company.schemes) {
        company.schemes.forEach((scheme) => {
          if (scheme.schemeName === "-" || scheme.schemeName.includes("_L")) {
            invalidSchemes++;
          }
        });
      }
    });

    console.log(`\n🔍 Found ${invalidSchemes} invalid schemes (should be 0)`);
  } catch (error) {
    console.error("❌ Error testing endpoint:", error.message);
    if (error.response) {
      console.error("Status:", error.response.status);
      console.error("Data:", error.response.data);
    }
  }
}

testCompaniesEndpoint();
