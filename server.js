require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cron = require("node-cron");
const ObjectId = mongoose.Types.ObjectId;

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://subikshapc:<db_password>@ligths.tncb6.mongodb.net/?retryWrites=true&w=majority&appName=Ligths";

const app = express();
app.use(
  cors({
    origin: "*", // Allow all origins for testing
    credentials: true,
  })
);
app.use(express.json());
app.use(bodyParser.json());

// 🔹 **MongoDB Connection**
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log("✅ Connected to MongoDB Atlas");
    // Fix any problematic indexes in the Goal collection
    await fixGoalIndexes();
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// 📌 Define Transaction Schema
const transactionSchema = new mongoose.Schema({
  name: { type: String, required: true },
  amount: { type: Number, required: true },
  type: { type: String, required: true }, // Expense, Income, Investment, etc.
  subType: { type: String }, // Optional - e.g., Food, Rent
  method: { type: String, required: true }, // Cash, Card, UPI, etc.
  date: { type: String, required: true }, // Store as ISO Date String
});

// 📌 Define Investment Schema
const investmentSchema = new mongoose.Schema({
  // Changed user field to store userName as String
  userName: { type: String, required: true },
  name: { type: String, required: true },
  amount: { type: Number, required: true }, // Initial investment amount
  currentAmount: { type: Number, required: true }, // Current value with interest
  interestRate: { type: Number, required: true }, // Annual interest rate (%)
  investmentType: { type: String, required: true }, // e.g., "Fixed Deposit", "Mutual Fund", etc.
  startDate: { type: Date, default: Date.now },
  maturityDate: { type: Date },
  lastInterestUpdate: { type: Date, default: Date.now },
  compoundingFrequency: { type: String, default: "daily" }, // daily, monthly, yearly
  description: { type: String },
  monthlyDeposit: { type: Number }, // Specific for Recurring Deposit
  duration: { type: Number }, // Specific for Recurring Deposit
  goalId: { type: String }, // Add goalId field
});

const Investment = mongoose.model("Investment", investmentSchema);

// 📌 Define Goal Schema
const goalSchema = new mongoose.Schema({
  // goalSchema is defined here FIRST
  userName: { type: String, required: true },
  name: { type: String, required: true },
  customName: { type: String },
  description: { type: String }, // Added this in previous step
  presentCost: { type: Number, required: true },
  childCurrentAge: { type: Number },
  goalAge: { type: Number },
  years: { type: Number },
  currentAge: { type: Number },
  inflation: { type: Number, default: 7.5 },
  returnRate: { type: Number, required: true },
  currentSip: { type: Number, default: 0 },
  investmentType: { type: String, default: "SIP/MF" },
  futureCost: { type: Number },
  required: { type: Number },
  futureValueOfSavings: { type: Number },
  monthlySIP: { type: Number },
  calculatedAt: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Goal = mongoose.model("Goal", goalSchema); // THEN the Goal model is created

// 📌 Define Mutual Fund NAV Schema
const mutualFundSchema = new mongoose.Schema({
  schemeCode: { type: String, required: true, unique: true },
  schemeName: { type: String, required: true },
  nav: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now },
});

const MutualFund = mongoose.model("MutualFund", mutualFundSchema);

// 🔹 **Fix Goal Collection Indexes**
const fixGoalIndexes = async () => {
  try {
    const indexes = await Goal.collection.getIndexes();
    console.log("📋 Current Goal collection indexes:", Object.keys(indexes));

    // Drop problematic indexes that prevent multiple goals per user
    const indexNames = Object.keys(indexes);
    for (const indexName of indexNames) {
      if (indexName.includes("email") || indexName.includes("userName_1")) {
        console.log(`🗑️ Dropping problematic index: ${indexName}`);
        await Goal.collection.dropIndex(indexName);
        console.log(`✅ Successfully dropped index: ${indexName}`);
      }
    }
  } catch (error) {
    console.log(
      "ℹ️ No problematic indexes found or error dropping indexes:",
      error.message
    );
  }
};

// 🔹 **Create User Model Dynamically**
const createUserModel = (userName) => {
  const collectionName = `${userName}`;

  console.log(`🔍 Creating model for collection: ${collectionName}`); // Add this log

  // ✅ Check if model already exists
  if (mongoose.models[collectionName]) {
    console.log(`✅ Using existing model for: ${collectionName}`);
    return mongoose.models[collectionName];
  }

  const UserSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    userName: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    age: { type: Number, required: true },
    retirementAge: { type: Number, required: true },
    phoneNumber: { type: String, required: true },
    country: { type: String, required: true },
    transactions: [
      {
        name: { type: String, required: true },
        amount: { type: Number, required: true },
        type: {
          type: String,
          required: true,
          enum: ["Income", "Investment", "Expense"],
        },
        subType: {
          type: String,
          required: function () {
            return this.type === "Expense";
          },
        },
        method: { type: String, required: true },
        date: { type: String, required: true },
      },
    ],
  });

  console.log(`✅ Creating new model for: ${collectionName}`);
  return mongoose.model(collectionName, UserSchema, collectionName);
};

app.post("/api/register", async (req, res) => {
  console.log("✅ Register route hit!");
  const {
    firstName,
    lastName,
    userName,
    email,
    password,
    age,
    retirementAge,
    phoneNumber,
    country,
  } = req.body;

  try {
    if (!userName || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required." });
    }

    // Check if the username already exists in the database
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    const existingCollection = collections.some(
      (col) => col.name === `${userName}`
    );

    if (existingCollection) {
      return res.status(400).json({ error: "Username already taken!" });
    }

    // Create a hashed password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User Model for the new user
    const UserModel = createUserModel(userName);
    const newUser = new UserModel({
      firstName,
      lastName,
      userName,
      email,
      password: hashedPassword,
      age,
      retirementAge,
      phoneNumber,
      country,
    });

    // Save User in a new collection with username
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/api/register", async (req, res) => {
  console.log("✅ Register route hit!");
  const {
    firstName,
    lastName,
    userName,
    email,
    password,
    age,
    retirementAge,
    phoneNumber,
    country,
  } = req.body;

  try {
    if (!userName || !email || !password) {
      return res
        .status(400)
        .json({ error: "Username, email, and password are required." });
    }

    // Check if the username already exists in the database
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    const existingCollection = collections.some(
      (col) => col.name === `${userName}`
    );

    if (existingCollection) {
      return res.status(400).json({ error: "Username already taken!" });
    }

    // Create a hashed password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User Model for the new user
    const UserModel = createUserModel(userName);
    const newUser = new UserModel({
      firstName,
      lastName,
      userName,
      email,
      password: hashedPassword,
      age,
      retirementAge,
      phoneNumber,
      country,
    });

    // Save User in a new collection with username
    await newUser.save();

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 Get User Profile Route
app.get("/profile/:userName", async (req, res) => {
  try {
    const { userName } = req.params;

    // Use the existing createUserModel function
    const UserModel = createUserModel(userName);

    // Find the user by userName
    const user = await UserModel.findOne({ userName });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return the user's profile
    const profile = {
      firstName: user.firstName,
      lastName: user.lastName,
      age: user.age,
      retirementAge: user.retirementAge,
      phoneNumber: user.phoneNumber,
      country: user.country,
      email: user.email,
      userName: user.userName,
    };

    res.status(200).json(profile);
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/profile/:userName", async (req, res) => {
  try {
    const { userName } = req.params;
    const updateData = req.body;

    // Validate required fields
    if (!updateData.firstName || !updateData.lastName) {
      return res
        .status(400)
        .json({ error: "First name and last name are required." });
    }

    // Create user model
    const UserModel = createUserModel(userName);

    // Find user
    const user = await UserModel.findOne({ userName });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Update allowed fields only (prevent updating sensitive fields like password)
    const allowedFields = [
      "firstName",
      "lastName",
      "phoneNumber",
      "country",
      "age",
      "retirementAge",
    ];

    allowedFields.forEach((field) => {
      if (updateData[field] !== undefined) {
        // Convert age and retirementAge to numbers if they are provided
        if (
          (field === "age" || field === "retirementAge") &&
          updateData[field]
        ) {
          user[field] = Number(updateData[field]);
        } else {
          user[field] = updateData[field];
        }
      }
    });

    // Save the updated user
    await user.save();

    // Return the updated profile
    const updatedProfile = {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      userName: user.userName,
      phoneNumber: user.phoneNumber,
      country: user.country,
      age: user.age,
      retirementAge: user.retirementAge,
    };

    res.status(200).json(updatedProfile);
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Get All Transactions for a User**
app.get("/transactions/:username", async (req, res) => {
  const { username } = req.params;

  try {
    console.log(`📚 Fetching transactions for user: ${username}`);
    const UserModel = createUserModel(username);

    // Correct lookup for user
    const user = await UserModel.findOne({ userName: username });

    if (!user) {
      console.log("❗ User not found!");
      return res.status(404).json({ error: "User not found!" });
    }

    // Filter out invalid/empty entries from transactions
    const validTransactions = user.transactions.filter(
      (transaction) => transaction && typeof transaction === "object"
    );

    console.log("✅ Cleaned Transactions:", validTransactions);
    res.status(200).json({ transactions: validTransactions });
  } catch (err) {
    console.error("Error fetching transactions:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// 📌 **User Login Route**
app.post("/api/login", async (req, res) => {
  console.log("🔐 Login route hit!");
  const { userName, password } = req.body;

  try {
    if (!userName || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    // Create UserModel for the given username
    const UserModel = createUserModel(userName);
    const user = await UserModel.findOne({ userName });

    if (!user) {
      console.log("❗ User not found!");
      return res.status(404).json({ error: "Invalid username or password." });
    }

    // ✅ Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("❗ Invalid password.");
      return res.status(401).json({ error: "Invalid username or password." });
    }

    // ✅ Generate JWT Token
    const payload = {
      id: user._id, // Keep user._id in payload for consistency if needed elsewhere, but use userName for investment lookup
      userName: user.userName,
    };

    console.log("🔐 JWT Payload:", payload);
    console.log("🔐 JWT_SECRET available:", JWT_SECRET ? "Yes" : "No");

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

    console.log("🔐 Generated token sample:", token.substring(0, 30) + "...");
    console.log("✅ Login successful!");
    res.status(200).json({
      message: "Login successful!",
      token,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.userName,
        email: user.email,
        age: user.age,
        retirementAge: user.retirementAge,
        phoneNumber: user.phoneNumber,
        country: user.country,
      },
    });
  } catch (error) {
    console.error("❌ Error during login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/transactions/:username", async (req, res) => {
  const { username } = req.params;
  const { name, amount, type, subType, method, date } = req.body;

  try {
    console.log(`🔍 Adding transaction for user: ${username}`);
    const UserModel = createUserModel(username);

    // Log model name to verify
    console.log(`✅ Model being used: ${UserModel.modelName}`);

    // Check if the model is valid
    if (!UserModel) {
      console.error(`❌ Model creation failed for username: ${username}`);
      return res.status(500).json({ error: "Error creating user model." });
    }

    const user = await UserModel.findOne({ userName: username });

    // Log user details
    console.log(`👤 Fetched user: ${user}`);

    if (!user) {
      console.log(`❌ User not found while adding transaction: ${username}`);
      return res.status(404).json({ error: "User not found!" });
    }

    // ✅ Push new transaction to the transactions array with createdAt
    const newTransaction = {
      name,
      amount,
      type,
      subType,
      method,
      date,
      createdAt: new Date().toISOString(), // Add current timestamp
    };

    const result = await UserModel.updateOne(
      { userName: username },
      {
        $push: {
          transactions: newTransaction,
        },
      }
    );

    console.log(`✅ Transaction added successfully!`, result);
    res.status(201).json({
      message: "Transaction added successfully!",
      transaction: newTransaction,
    });
  } catch (err) {
    console.error("❌ Error adding transaction:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Check Username Availability**
app.post("/api/check-username", async (req, res) => {
  const { userName } = req.body;

  try {
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    const userExists = collections.some((col) => col.name === `${userName}`);

    res.json({ exists: userExists });
  } catch (error) {
    console.error("Error checking username:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Check Email Availability**
app.post("/api/check-email", async (req, res) => {
  const { email } = req.body;

  // Basic Email Validation Regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!email || !emailRegex.test(email)) {
    return res
      .status(400)
      .json({ error: "Please enter a valid email address" });
  }

  try {
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    let emailExists = false;

    for (const collection of collections) {
      const modelName = collection.name;

      // Skip system collections
      if (modelName.startsWith("system.")) continue;

      const UserModel = createUserModel(modelName.replace("", ""));
      const existingUser = await UserModel.findOne({ email });
      if (existingUser) {
        emailExists = true;
        break;
      }
    }

    res.json({ exists: emailExists });
  } catch (error) {
    console.error("Error checking email:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.delete("/transactions/:username/:id", async (req, res) => {
  const { username, id } = req.params;
  console.log(`🗑️ Deleting transaction with ID: ${id} for user: ${username}`);

  try {
    // ✅ Create the user model dynamically
    const UserModel = createUserModel(username);

    // ✅ Validate the ObjectId format
    if (!ObjectId.isValid(id)) {
      console.log("❗ Invalid ObjectId format");
      return res.status(400).json({ error: "Invalid transaction ID." });
    }

    // ✅ Check if the transaction exists
    const user = await UserModel.findOne({ userName: username });

    if (!user) {
      console.log(`❗ User ${username} not found.`);
      return res.status(404).json({ error: "User not found." });
    }

    const transactionIndex = user.transactions.findIndex(
      (transaction) => transaction._id.toString() === id
    );

    if (transactionIndex === -1) {
      console.log("❌ Transaction not found.");
      return res.status(404).json({ error: "Transaction not found." });
    }

    // ✅ Optional: Fix invalid transactions before deleting
    const invalidTransactions = user.transactions.filter(
      (transaction) => !transaction.subType
    );

    if (invalidTransactions.length > 0) {
      console.log(
        `⚠️ Found ${invalidTransactions.length} invalid transactions. Fixing them...`
      );
      user.transactions.forEach((transaction) => {
        if (!transaction.subType) {
          transaction.subType = "Other"; // Default value
        }
      });

      await user.save();
      console.log("✅ Invalid transactions fixed!");
    }

    // ✅ Remove the transaction by index
    user.transactions.splice(transactionIndex, 1);

    // ✅ Save without validation
    await user.save({ validateBeforeSave: false });

    console.log(`✅ Transaction deleted successfully!`);
    res
      .status(200)
      .json({ success: true, message: "Transaction deleted successfully." });
  } catch (error) {
    console.error("❌ Error deleting transaction:", error);
    res.status(500).json({ error: "Error deleting transaction." });
  }
});

app.get("/api/inflation-data", (req, res) => {
  try {
    const inflationData = require("./inflation_data.json");
    res.json(inflationData);
  } catch (error) {
    console.error("Error loading inflation data:", error);
    res.status(500).json({ error: "Failed to retrieve inflation data" });
  }
});

app.get("/transactions/:username/monthly-essential", async (req, res) => {
  const { username } = req.params;
  const { includeToday } = req.query; // Add query parameter to optionally include today's expenses

  try {
    const UserModel = createUserModel(username);
    const user = await UserModel.findOne({ userName: username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Filter essential expenses
    const essentialExpenses = user.transactions.filter(
      (transaction) =>
        transaction.type === "Expense" && transaction.subType === "Essential"
    );

    if (essentialExpenses.length === 0) {
      return res.json({
        monthlyAverage: "0.00",
        dailyAverage: "0.00",
        days: 0,
        months: 0,
        totalAmount: 0,
        expenses: [],
      });
    }

    // Get today's date in YYYY-MM-DD format
    const today = new Date();
    const todayString = `${today.getFullYear()}-${String(
      today.getMonth() + 1
    ).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;

    // Verify dates and filter out invalid ones (but include today if requested)
    const validExpenses = essentialExpenses.filter((expense) => {
      try {
        const date = new Date(expense.date);
        // Filter out invalid dates, but conditionally include today's expenses
        return (
          !isNaN(date) &&
          date.getFullYear() >= 2000 &&
          (includeToday === "true" || expense.date !== todayString)
        );
      } catch (e) {
        return false;
      }
    });

    // If no valid expenses left after filtering
    if (validExpenses.length === 0) {
      return res.json({
        monthlyAverage: "0.00",
        dailyAverage: "0.00",
        days: 0,
        months: 0,
        totalAmount: 0,
        expenses: [],
      });
    }

    // Calculate total amount
    const totalAmount = validExpenses.reduce(
      (sum, expense) => sum + expense.amount,
      0
    );

    // Count unique days of expenses
    const uniqueDays = new Set(
      validExpenses.map((expense) => expense.date.substring(0, 10))
    ).size;

    // Sort expenses by date
    const sortedExpenses = [...validExpenses].sort(
      (a, b) => new Date(a.date) - new Date(b.date)
    );

    const earliestDate = new Date(sortedExpenses[0].date);
    const latestDate = new Date(sortedExpenses[sortedExpenses.length - 1].date);

    // Calculate months span for informational purposes
    const monthsSpan =
      (latestDate.getFullYear() - earliestDate.getFullYear()) * 12 +
      (latestDate.getMonth() - earliestDate.getMonth()) +
      1;

    // Calculate average per day of expenses
    const avgPerDay = totalAmount / uniqueDays;

    // Calculate monthly projection (daily average * 30)
    const monthlyProjection = avgPerDay * 30;

    res.json({
      monthlyAverage: monthlyProjection.toFixed(2),
      dailyAverage: avgPerDay.toFixed(2),
      uniqueDays: uniqueDays,
      months: monthsSpan,
      totalAmount: totalAmount.toFixed(2),
      expenses: validExpenses,
      dateRange: {
        earliest: earliestDate.toISOString(),
        latest: latestDate.toISOString(),
      },
      calculationMethod: "Total expenses ÷ unique days with expenses × 30 days",
    });
  } catch (err) {
    console.error("Error calculating monthly expenses:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 JWT Token Verification Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");
  console.log("🔑 Full Authorization header:", authHeader);

  const token = authHeader?.replace("Bearer ", "");

  console.log(
    "🔑 Verifying token:",
    token ? token.substring(0, 20) + "..." : "No token"
  );

  if (!token) {
    console.log("❌ No token provided");
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    console.log(
      "🔍 JWT_SECRET being used:",
      JWT_SECRET ? "Available" : "Missing"
    );
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("✅ Token decoded successfully:", decoded);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("❌ Token verification failed:");
    console.error("- Error name:", err.name);
    console.error("- Error message:", err.message);
    console.error(
      "- Token sample:",
      token ? token.substring(0, 30) + "..." : "No token"
    );

    // Provide more specific error messages
    if (err.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ error: "Token has expired. Please login again." });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).json({ error: "Invalid token format." });
    } else if (err.name === "NotBeforeError") {
      return res.status(401).json({ error: "Token not active yet." });
    }

    res.status(400).json({ error: "Invalid token." });
  }
};

// 📌 Function to update daily interest for all investments
const updateDailyInterest = async () => {
  try {
    const investments = await Investment.find({});

    for (const investment of investments) {
      const now = new Date();
      const lastUpdate = new Date(investment.lastInterestUpdate);

      // Calculate days since last update
      const daysDiff = Math.floor((now - lastUpdate) / (1000 * 60 * 60 * 24));

      if (daysDiff > 0) {
        // Calculate daily interest rate
        const dailyRate = investment.interestRate / 100 / 365;

        // Apply compound interest for the number of days
        const newAmount =
          investment.currentAmount * Math.pow(1 + dailyRate, daysDiff);

        // Update the investment
        await Investment.findByIdAndUpdate(investment._id, {
          currentAmount: newAmount,
          lastInterestUpdate: now,
        });
      }
    }

    console.log("Daily interest updated for all investments");
  } catch (err) {
    console.error("Error updating daily interest:", err);
  }
};

// Run interest calculation daily (optional - you can use a proper cron job)
setInterval(updateDailyInterest, 24 * 60 * 60 * 1000); // Run every 24 hours

// 📌 **Goal Routes**

// Test endpoint to verify connectivity
app.get("/test", async (req, res) => {
  console.log(
    "🔍 Test endpoint hit from:",
    req.ip,
    "at",
    new Date().toISOString()
  );
  res.status(200).json({
    message: "Server is working!",
    timestamp: new Date().toISOString(),
    ip: req.ip,
  });
});

// Get all goals for a user
app.get("/goals/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const goals = await Goal.find({ userName: username }).sort({
      createdAt: -1,
    });
    res.status(200).json(goals);
  } catch (error) {
    console.error(`Error fetching goals for ${username}:`, error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Create a new goal
app.post("/goals/:username", async (req, res) => {
  const { username } = req.params;
  const goalData = req.body;

  console.log(
    `Received goal data for ${username}:`,
    JSON.stringify(goalData, null, 2)
  );

  try {
    // Add a debug endpoint info
    console.log(
      `POST /goals/${username} endpoint hit at:`,
      new Date().toISOString()
    );

    // Validate required fields with improved logic
    const requiredFields = ["name", "presentCost", "returnRate"];
    const missingFields = requiredFields.filter((field) => {
      const value = goalData[field];
      // For returnRate, specifically check if it's a number (including 0)
      if (field === "returnRate") {
        return (
          value === undefined ||
          value === null ||
          value === "" ||
          isNaN(Number(value))
        );
      }
      // For other fields, check if they're missing or empty
      return value === undefined || value === null || value === "";
    });

    console.log(`Validation check - Missing fields:`, missingFields);
    console.log(
      `ReturnRate value:`,
      goalData.returnRate,
      `Type:`,
      typeof goalData.returnRate
    );

    if (missingFields.length > 0) {
      console.log(
        `Validation failed - missing fields: ${missingFields.join(", ")}`
      );
      return res.status(400).json({
        error: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Ensure numeric fields are valid
    const numericFields = [
      "presentCost",
      "returnRate",
      "currentSip",
      "inflation",
      "childCurrentAge",
      "goalAge",
      "years",
      "currentAge",
      "futureCost", // Add calculated fields to numeric validation
      "required",
      "futureValueOfSavings",
      "monthlySIP",
    ];

    console.log("Starting numeric validation...");

    for (const field of numericFields) {
      // Only validate if the field exists in goalData and is not a valid number
      if (
        goalData[field] !== undefined &&
        goalData[field] !== null &&
        isNaN(parseFloat(goalData[field]))
      ) {
        console.log(
          `Numeric validation failed for field '${field}' with value:`,
          goalData[field]
        );
        return res
          .status(400)
          .json({ error: `${field} must be a valid number` });
      } else if (goalData[field] !== undefined && goalData[field] !== null) {
        console.log(
          `Field '${field}' validated successfully:`,
          goalData[field],
          "->",
          parseFloat(goalData[field])
        );
      }
    }

    console.log("Numeric validation passed. Creating goal object...");

    // Explicitly create the new goal object, parsing values and handling defaults/optionality
    const newGoal = new Goal({
      userName: username,
      name: goalData.name,
      customName: goalData.customName || undefined, // Set to undefined if empty string or null
      description: goalData.description || undefined, // Ensure description is included
      presentCost: parseFloat(goalData.presentCost),
      // Handle optional fields: if they exist, parse them, otherwise leave undefined/null
      childCurrentAge: goalData.childCurrentAge
        ? parseFloat(goalData.childCurrentAge)
        : undefined,
      goalAge: goalData.goalAge ? parseFloat(goalData.goalAge) : undefined,
      years: goalData.years ? parseFloat(goalData.years) : undefined,
      currentAge: goalData.currentAge
        ? parseFloat(goalData.currentAge)
        : undefined,
      inflation: parseFloat(goalData.inflation || 7.5), // Use default if frontend doesn't send
      returnRate: parseFloat(goalData.returnRate),
      currentSip: parseFloat(goalData.currentSip || 0), // Use default if frontend sends empty/null
      investmentType: goalData.investmentType || "SIP/MF",
      // Include calculated fields from frontend
      futureCost: goalData.futureCost
        ? parseFloat(goalData.futureCost)
        : undefined,
      required: goalData.required ? parseFloat(goalData.required) : undefined,
      futureValueOfSavings: goalData.futureValueOfSavings
        ? parseFloat(goalData.futureValueOfSavings)
        : undefined,
      monthlySIP: goalData.monthlySIP
        ? parseFloat(goalData.monthlySIP)
        : undefined,
      calculatedAt: new Date().toLocaleString(), // Server-side timestamp
      updatedAt: new Date(), // Add updatedAt timestamp
      // createdAt is handled by Mongoose default
    });

    console.log("Goal object created successfully, attempting to save...");

    const savedGoal = await newGoal.save();

    console.log("Goal saved successfully to database:", savedGoal._id);

    res.status(201).json(savedGoal);
  } catch (error) {
    console.error(`Error creating goal for ${username}:`, error.stack); // This is key for debugging on server logs
    if (error.name === "ValidationError") {
      // Mongoose validation error (e.g., required field missing, type mismatch)
      console.error("Mongoose Validation errors:", error.errors);
      // Construct a more user-friendly error message from Mongoose validation errors
      const errors = Object.keys(error.errors).map(
        (key) => error.errors[key].message
      );
      return res
        .status(400)
        .json({ error: `Validation failed: ${errors.join(", ")}` });
    } else if (error.name === "MongoError") {
      // MongoDB specific error (e.g., connection issue, duplicate key)
      console.error("MongoDB error:", error.message);
      return res
        .status(500)
        .json({ error: "Database operation failed. Please try again." });
    }
    // Catch-all for any other unexpected errors
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ... existing code ...

// Update a goal
app.put("/goals/:username/:id", async (req, res) => {
  const { username, id } = req.params;
  const updateData = req.body;

  try {
    const updatedGoal = await Goal.findOneAndUpdate(
      { _id: id, userName: username },
      {
        ...updateData,
        calculatedAt: new Date().toLocaleString(),
        updatedAt: new Date(),
      },
      { new: true }
    );

    if (!updatedGoal) {
      return res.status(404).json({ error: "Goal not found" });
    }

    res.status(200).json(updatedGoal);
  } catch (error) {
    console.error("Error updating goal:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Delete a goal
app.delete("/goals/:username/:id", async (req, res) => {
  const { username, id } = req.params;

  try {
    const deletedGoal = await Goal.findOneAndDelete({
      _id: id,
      userName: username,
    });

    if (!deletedGoal) {
      return res.status(404).json({ error: "Goal not found" });
    }

    res.status(200).json({ message: "Goal deleted successfully" });
  } catch (error) {
    console.error("Error deleting goal:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Get investments by goal (placeholder for future integration)
app.get("/investments/:username/by-goal/:goalId", async (req, res) => {
  const { username, goalId } = req.params;

  try {
    // This is a placeholder for when you integrate with actual investment tracking
    // For now, return empty data
    res.status(200).json({
      totalInvested: 0,
      monthlySip: 0,
      investments: [],
    });
  } catch (error) {
    console.error("Error fetching investments by goal:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Investment Routes**

// --- FIX STARTS HERE ---
// Add a new investment (REWRITTEN FOR CLARITY AND SECURITY)
app.post("/investment", verifyToken, async (req, res) => {
  try {
    console.log("💰 Creating investment for user:", req.user.userName);
    console.log("💰 Received Investment data:", req.body);

    // Explicitly pull only the fields you expect from the body
    const {
      name,
      amount,
      interestRate,
      investmentType,
      maturityDate,
      description,
      goalId, // Explicitly get the goalId
      compoundingFrequency,
      monthlyDeposit,
      duration,
    } = req.body;

    // Basic validation
    if (
      !name ||
      !amount ||
      interestRate === undefined ||
      interestRate === null ||
      !investmentType
    ) {
      return res
        .status(400)
        .json({ error: "Missing required investment fields." });
    }

    const newInvestment = new Investment({
      name,
      amount: parseFloat(amount),
      currentAmount: parseFloat(amount), // currentAmount is same as initial amount
      interestRate: parseFloat(interestRate),
      investmentType,
      startDate: new Date(),
      maturityDate,
      description,
      goalId, // Pass the extracted goalId
      compoundingFrequency,
      monthlyDeposit,
      duration,
      userName: req.user.userName, // Add userName from the verified token
    });

    await newInvestment.save();
    console.log("✅ Investment created successfully:", newInvestment._id);

    // Respond with 201 Created status and the new investment object
    res.status(201).json(newInvestment);
  } catch (err) {
    console.error("❌ Error creating investment:", err);
    res.status(500).json({ error: err.message || "Failed to add investment" });
  }
});
// --- FIX ENDS HERE ---

// 📌 Test endpoint to debug token and user issues
app.get("/test-token", verifyToken, async (req, res) => {
  try {
    console.log("🧪 Test token endpoint - User from token:", req.user);

    // Check if user exists in database
    const UserModel = createUserModel(req.user.userName);
    const user = await UserModel.findById(req.user.id);

    console.log("🧪 User found in DB:", user ? "Yes" : "No");

    // Check investments count
    const userName = req.user.userName; // Changed from userId = new mongoose.Types.ObjectId(req.user.id);
    const investmentCount = await Investment.countDocuments({
      userName: userName,
    }); // Changed from user: userId
    console.log("🧪 Investment count for user:", investmentCount);

    res.json({
      message: "Token is valid",
      user: req.user,
      userExistsInDB: !!user,
      investmentCount,
      // Removed userIdType and userIdAsObjectId as they are less relevant with userName filtering
    });
  } catch (err) {
    console.error("🧪 Test token error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 📌 Simple token test without ObjectId conversion
app.get("/test-simple", verifyToken, async (req, res) => {
  try {
    console.log("🧪 Simple test - User from token:", req.user);
    res.json({
      message: "Token verification successful",
      user: req.user,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("🧪 Simple test error:", err);
    res.status(500).json({ error: err.message });
  }
});

// 📌 Simple test endpoint to check token validation
app.get("/test-auth", verifyToken, (req, res) => {
  res.json({
    message: "Token is valid!",
    user: req.user,
    timestamp: new Date().toISOString(),
  });
});

// Get all investments
app.get("/investments", verifyToken, async (req, res) => {
  try {
    console.log("📊 Getting investments for user:", req.user.userName); // Changed from req.user.id
    console.log("📊 User object:", req.user);

    const userName = req.user.userName; // Changed from userId = new mongoose.Types.ObjectId(req.user.id);
    const investments = await Investment.find({ userName: userName }); // Changed from user: userId
    console.log("📊 Found investments:", investments.length);

    res.json(investments);
  } catch (err) {
    console.error("❌ Error fetching investments:", err);
    res.status(500).json({ error: err.message });
  }
});

// Update investment
app.put("/investment/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName; // Changed from userId = new mongoose.Types.ObjectId(req.user.id);
    const investment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
    }); // Changed from user: userId

    if (!investment) {
      return res
        .status(404)
        .json({ error: "Investment not found or not authorized" });
    }

    const updatedInvestment = await Investment.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(updatedInvestment);
  } catch (err) {
    res.status(500).json(err);
  }
});

// Delete investment
app.delete("/investment/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName; // Changed from userId = new mongoose.Types.ObjectId(req.user.id);
    const investment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
    }); // Changed from user: userId

    if (!investment) {
      return res
        .status(404)
        .json({ error: "Investment not found or not authorized" });
    }

    await Investment.findByIdAndDelete(req.params.id);
    res.json({ message: "Investment deleted" });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Manually trigger interest calculation (for testing)
app.post("/calculate-interest", verifyToken, async (req, res) => {
  try {
    await updateDailyInterest();
    res.json({ message: "Interest calculation triggered successfully" });
  } catch (err) {
    res.status(500).json(err);
  }
});

// 🔹 **Fetch NAV Data from AMFI**
const fetchAndStoreNAVData = async () => {
  try {
    console.log("📈 Fetching NAV data from AMFI...");
    const response = await axios.get(
      "https://www.amfiindia.com/spages/NAVAll.txt"
    );
    const data = response.data;

    // Parse the NAV data
    const lines = data.split("\n");
    let foundData = false;

    for (const line of lines) {
      if (line.trim() === "") continue;

      // Skip header lines until we find actual data
      if (
        line.includes("Scheme Code") ||
        line.includes("ISIN") ||
        line.includes("Open Ended")
      ) {
        foundData = true;
        continue;
      }

      if (!foundData) continue;

      // Parse each line: SchemeCode;ISINDivPayoutISINGrowth;SchemeName;NetAssetValue;RepurchasePrice;SalePrice;Date
      const parts = line.split(";");
      if (parts.length >= 4) {
        const schemeCode = parts[0].trim();
        const schemeName = parts[2].trim();
        const nav = parseFloat(parts[3].trim());

        // Skip invalid entries
        if (!schemeCode || !schemeName || isNaN(nav) || nav <= 0) continue;

        // Update or create mutual fund entry
        await MutualFund.findOneAndUpdate(
          { schemeCode: schemeCode },
          {
            schemeCode: schemeCode,
            schemeName: schemeName,
            nav: nav,
            lastUpdated: new Date(),
          },
          { upsert: true, new: true }
        );
      }
    }

    console.log("✅ NAV data updated successfully");
  } catch (error) {
    console.error("❌ Error fetching NAV data:", error.message);
  }
};

// 🔹 **Schedule Daily NAV Update**
// Run every day at 9:15 PM (when AMFI typically updates NAV)
cron.schedule("15 21 * * *", fetchAndStoreNAVData);

// Initial fetch on server start
fetchAndStoreNAVData();

// 🔹 **Mutual Fund API Endpoints**

// Get all mutual funds with pagination
app.get("/mutualfunds", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || "";

    // Check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      // Return mock data when MongoDB is not connected
      const mockFunds = [
        {
          schemeCode: "120503",
          schemeName:
            "Aditya Birla Sun Life Frontline Equity Fund - Direct Plan - Growth",
          nav: 587.23,
          lastUpdated: new Date(),
        },
        {
          schemeCode: "120504",
          schemeName:
            "Aditya Birla Sun Life Tax Relief 96 - Direct Plan - Growth",
          nav: 156.45,
          lastUpdated: new Date(),
        },
        {
          schemeCode: "120505",
          schemeName:
            "Aditya Birla Sun Life Banking & Financial Services Fund - Direct Plan - Growth",
          nav: 234.67,
          lastUpdated: new Date(),
        },
      ];

      const filtered = search
        ? mockFunds.filter((fund) =>
            fund.schemeName.toLowerCase().includes(search.toLowerCase())
          )
        : mockFunds;

      return res.json({
        funds: filtered.slice((page - 1) * limit, page * limit),
        totalPages: Math.ceil(filtered.length / limit),
        currentPage: page,
        totalFunds: filtered.length,
      });
    }

    const query = search
      ? { schemeName: { $regex: search, $options: "i" } }
      : {};

    const totalFunds = await MutualFund.countDocuments(query);
    const funds = await MutualFund.find(query)
      .sort({ schemeName: 1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      funds,
      totalPages: Math.ceil(totalFunds / limit),
      currentPage: page,
      totalFunds,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get specific mutual fund by scheme code
app.get("/mutualfunds/:schemeCode", async (req, res) => {
  try {
    const fund = await MutualFund.findOne({
      schemeCode: req.params.schemeCode,
    });
    if (!fund) {
      return res.status(404).json({ error: "Mutual fund not found" });
    }
    res.json(fund);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Manual NAV update trigger (for testing)
app.post("/update-nav", async (req, res) => {
  try {
    await fetchAndStoreNAVData();
    res.json({ message: "NAV data updated successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🔹 **Additional API Routes for NAV (as requested)**
// GET /api/nav - Alternative route for NAV data
app.get("/api/nav", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || "";

    const query = search
      ? { schemeName: { $regex: search, $options: "i" } }
      : {};

    const totalFunds = await MutualFund.countDocuments(query);
    const funds = await MutualFund.find(query)
      .sort({ schemeName: 1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      success: true,
      data: funds,
      pagination: {
        totalFunds,
        totalPages: Math.ceil(totalFunds / limit),
        currentPage: page,
        limit,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// 🔹 **Start Server**
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Mobile devices can connect at: http://10.69.228.236:${PORT}`);
  console.log(`💻 Local access: http://localhost:${PORT}`);
});
