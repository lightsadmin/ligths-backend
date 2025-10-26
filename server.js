require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cron = require("node-cron");
const stockService = require("./htqaat");
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
  .connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("✅ Connected to MongoDB Atlas");
    // Fix any problematic indexes in the Goal collection
    await fixGoalIndexes();
    // Fix any problematic indexes in the StockPortfolio collection
    await fixStockPortfolioIndexes();
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
  investmentType: { type: String, required: true }, // e.g., "Fixed Deposit", "Mutual Fund", "Stock", etc.
  startDate: { type: Date, default: Date.now },
  maturityDate: { type: Date },
  lastInterestUpdate: { type: Date, default: Date.now },
  compoundingFrequency: { type: String, default: "daily" }, // daily, monthly, yearly
  description: { type: String },
  monthlyDeposit: { type: Number }, // Specific for Recurring Deposit
  duration: { type: Number }, // Specific for Recurring Deposit
  goalId: { type: String }, // Add goalId field
  // Stock-specific fields
  stockSymbol: { type: String }, // e.g., "AAPL", "MSFT"
  stockQuantity: { type: Number }, // Number of shares (can be negative for sells)
  stockPrice: { type: Number }, // Price per share when bought/sold
  // Mutual Fund specific fields
  schemeCode: { type: String }, // MF scheme code
  schemeName: { type: String }, // Full scheme name
  units: { type: Number }, // Number of units purchased
  nav: { type: Number }, // NAV at purchase
  currentNAV: { type: Number }, // Current NAV
  averageNAV: { type: Number }, // Average NAV for SIP investments
  sipDate: { type: Number }, // SIP date (1-31)
  calculationType: { type: String }, // "SIP" or "LUMPSUM"
  investmentDate: { type: Date }, // Investment date
});

const Investment = mongoose.model("Investment", investmentSchema);

// 📌 Define Stock Portfolio Schema (separate from general investments)
const stockPortfolioSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  originalUserName: { type: String }, // Backup field for original userName when workaround is used
  symbol: { type: String, required: true },
  name: { type: String, required: true },
  exchange: { type: String, required: true },
  quantity: { type: Number, required: true },
  purchasePrice: { type: Number, required: true },
  currentPrice: { type: Number, default: 0 },
  investmentType: { type: String, default: "stock" },
  notes: { type: String },
  dateAdded: { type: Date, default: Date.now },
  // Auto-delete after 1 week
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    index: { expireAfterSeconds: 0 }, // MongoDB TTL index for auto-deletion
  },
});

const StockPortfolio = mongoose.model("StockPortfolio", stockPortfolioSchema);

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

const mutualFundSchema = new mongoose.Schema({
  schemeCode: { type: String, required: true, unique: true },
  schemeName: { type: String, required: true },
  nav: { type: Number, required: true },
  lastUpdated: { type: Date, default: Date.now },
});
const MutualFund = mongoose.model("MutualFund", mutualFundSchema);

// 📌 Define Stock Schema for NSE/BSE stocks
const stockSchema = new mongoose.Schema({
  symbol: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  exchange: { type: String, required: true }, // NSE, BSE
  currentPrice: { type: Number },
  dayChange: { type: Number },
  dayChangePercent: { type: Number },
  volume: { type: Number },
  marketCap: { type: Number },
  lastUpdated: { type: Date, default: Date.now },
});
const Stock = mongoose.model("Stock", stockSchema);

// Initialize stock service with the model
stockService.setStockModel(Stock);

// ...existing code...

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

// 🔹 **Fix StockPortfolio Collection Indexes**
const fixStockPortfolioIndexes = async () => {
  try {
    const collection = StockPortfolio.collection;
    const indexes = await collection.getIndexes();
    console.log(
      "📋 Current StockPortfolio collection indexes:",
      Object.keys(indexes)
    );

    // Step 1: Drop ALL indexes except _id (most aggressive approach)
    const indexNames = Object.keys(indexes);
    for (const indexName of indexNames) {
      if (indexName !== "_id_") {
        console.log(`🗑️ Dropping index: ${indexName}`);
        try {
          await collection.dropIndex(indexName);
          console.log(`✅ Successfully dropped index: ${indexName}`);
        } catch (dropError) {
          console.log(`⚠️ Could not drop ${indexName}:`, dropError.message);
        }
      }
    }

    // Step 2: Wait a moment for the drops to complete
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Step 3: Create only the indexes we need
    try {
      // Compound index for userName + symbol + dateAdded (NO unique constraint)
      await collection.createIndex(
        { userName: 1, symbol: 1, dateAdded: -1 },
        { background: true }
      );
      console.log("✅ Created compound index: userName + symbol + dateAdded");
    } catch (createError) {
      console.log("ℹ️ Compound index creation failed:", createError.message);
    }

    try {
      // TTL index for auto-deletion
      await collection.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, background: true }
      );
      console.log("✅ Created TTL index for auto-deletion");
    } catch (ttlError) {
      console.log("ℹ️ TTL index creation failed:", ttlError.message);
    }

    // Step 4: Verify final indexes
    const finalIndexes = await collection.getIndexes();
    console.log("📋 Final StockPortfolio indexes:", Object.keys(finalIndexes));
  } catch (error) {
    console.log("ℹ️ Error managing StockPortfolio indexes:", error.message);
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
    securityPin: { type: String, required: true }, // For forgot password functionality
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
    securityPin,
  } = req.body;

  try {
    if (!userName || !email || !password || !securityPin) {
      return res.status(400).json({
        error: "Username, email, password, and security PIN are required.",
      });
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

    // Create a hashed password and security PIN with enhanced security
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecurityPin = await bcrypt.hash(securityPin, saltRounds);

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
      securityPin: hashedSecurityPin,
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

    // Check if userName is actually an email address
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isEmail = emailRegex.test(userName);

    let foundUser = null;
    let UserModel = null;

    if (isEmail) {
      // If it's an email, search across all collections like in forgot password
      console.log(`🔍 Login with email: ${userName}`);
      const collections = await mongoose.connection.db
        .listCollections()
        .toArray();

      for (const collection of collections) {
        const collectionName = collection.name;
        if (collectionName.startsWith("system.")) continue;

        try {
          const TempUserModel = createUserModel(collectionName);
          const user = await TempUserModel.findOne({ email: userName });

          if (user) {
            foundUser = user;
            UserModel = TempUserModel;
            console.log(
              `🔍 Found user by email: ${user.userName}, Email: ${user.email}`
            );
            break;
          }
        } catch (err) {
          continue;
        }
      }
    } else {
      // If it's a username, use the original logic
      console.log(`🔍 Login with username: ${userName}`);
      UserModel = createUserModel(userName);
      foundUser = await UserModel.findOne({ userName });
    }

    if (!foundUser) {
      console.log("❗ User not found!");
      return res.status(404).json({ error: "Invalid username or password." });
    }

    // ✅ Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, foundUser.password);
    if (!isMatch) {
      console.log("❗ Invalid password.");
      return res.status(401).json({ error: "Invalid username or password." });
    }

    // ✅ Generate JWT Token
    const payload = {
      id: foundUser._id, // Keep user._id in payload for consistency if needed elsewhere, but use userName for investment lookup
      userName: foundUser.userName,
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
        firstName: foundUser.firstName,
        lastName: foundUser.lastName,
        username: foundUser.userName,
        email: foundUser.email,
        age: foundUser.age,
        retirementAge: foundUser.retirementAge,
        phoneNumber: foundUser.phoneNumber,
        country: foundUser.country,
      },
    });
  } catch (error) {
    console.error("❌ Error during login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔹 **Forgot Password Route (Security PIN based)**
app.post("/api/forgot-password", async (req, res) => {
  console.log("🔐 Forgot password route hit!");
  const { email, securityPin, newPassword } = req.body;

  try {
    // Sanitize inputs to prevent injection attacks
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedSecurityPin = securityPin
      .trim()
      .replace(/[^a-zA-Z0-9]/g, "");
    const sanitizedNewPassword = newPassword.trim();

    // Rate limiting check
    const clientIP = req.ip || req.connection.remoteAddress;
    const attemptKey = `${sanitizedEmail}-${clientIP}`;
    const now = Date.now();

    const forgotPasswordAttempts = new Map();
    const MAX_FORGOT_PASSWORD_ATTEMPTS = 3;
    const FORGOT_PASSWORD_WINDOW = 15 * 60 * 1000; // 15 minutes

    if (forgotPasswordAttempts.has(attemptKey)) {
      const attempts = forgotPasswordAttempts.get(attemptKey);
      const recentAttempts = attempts.filter(
        (time) => now - time < FORGOT_PASSWORD_WINDOW
      );

      if (recentAttempts.length >= MAX_FORGOT_PASSWORD_ATTEMPTS) {
        return res.status(429).json({
          error: "Too many password reset attempts. Please try again later.",
        });
      }

      forgotPasswordAttempts.set(attemptKey, [...recentAttempts, now]);
    } else {
      forgotPasswordAttempts.set(attemptKey, [now]);
    }

    // Input validation
    if (!email || !securityPin || !newPassword) {
      return res.status(400).json({
        error: "Email, security PIN, and new password are required.",
      });
    }

    // Security PIN validation
    if (sanitizedSecurityPin.length < 4 || sanitizedSecurityPin.length > 6) {
      return res.status(400).json({
        error: "Security PIN must be 4-6 characters.",
      });
    }

    // Password strength validation
    if (newPassword.length < 6) {
      return res.status(400).json({
        error: "New password must be at least 6 characters long.",
      });
    }

    // Find user by email - email should be unique per user
    let foundUser = null;
    let userModel = null;

    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();

    for (const collection of collections) {
      const collectionName = collection.name;

      // Skip system collections
      if (collectionName.startsWith("system.")) continue;

      try {
        const UserModel = createUserModel(collectionName);
        const user = await UserModel.findOne({ email: sanitizedEmail });

        if (user) {
          foundUser = user;
          userModel = UserModel;
          console.log(`🔍 Found user: ${user.userName}, Email: ${user.email}`);
          break; // Email is unique, so we can break after finding the user
        }
      } catch (err) {
        // Skip collections that might not be user collections
        continue;
      }
    }

    if (!foundUser) {
      console.log(`❌ No user found with email: ${sanitizedEmail}`);
      return res
        .status(404)
        .json({ error: "No account found with this email address." });
    }

    // Check if user has a security PIN set
    if (!foundUser.securityPin) {
      console.log(`⚠️ User ${foundUser.userName} security setup required.`);

      // Hash the provided security PIN with enhanced security (12 rounds + salt)
      const saltRounds = 12;
      const hashedSecurityPin = await bcrypt.hash(
        sanitizedSecurityPin,
        saltRounds
      );

      // Update user with security PIN
      await userModel.findByIdAndUpdate(foundUser._id, {
        securityPin: hashedSecurityPin,
      });

      console.log(
        `✅ Security setup completed for user: ${foundUser.userName}`
      );

      // Continue with password reset process
      foundUser.securityPin = hashedSecurityPin; // Update local object
    }

    console.log(
      `✅ User ${foundUser.userName} found with security PIN. Proceeding with verification...`
    );

    // Verify security PIN
    const isPinValid = await bcrypt.compare(
      sanitizedSecurityPin,
      foundUser.securityPin
    );
    if (!isPinValid) {
      return res.status(401).json({ error: "Invalid security PIN." });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(sanitizedNewPassword, 10);

    // Update user password
    await userModel.findByIdAndUpdate(foundUser._id, {
      password: hashedNewPassword,
    });

    // Clear rate limiting attempts on successful reset
    forgotPasswordAttempts.delete(attemptKey);

    console.log(`✅ Password reset successful for user: ${foundUser.userName}`);

    res.status(200).json({
      message:
        "Password reset successful! You can now log in with your new password.",
    });
  } catch (error) {
    console.error("❌ Error in forgot password:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔍 **Check Security PIN Status Route**
app.post("/api/check-security-pin", async (req, res) => {
  console.log("🔍 Check security PIN route hit!");
  const { email } = req.body;

  try {
    // Input validation
    if (!email) {
      return res.status(400).json({
        error: "Email is required.",
      });
    }

    // Find user by email across all collections
    let foundUser = null;

    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();

    for (const collection of collections) {
      const collectionName = collection.name;

      // Skip system collections
      if (collectionName.startsWith("system.")) continue;

      try {
        const UserModel = createUserModel(collectionName);
        const user = await UserModel.findOne({ email: email });

        if (user) {
          foundUser = user;
          console.log(
            `🔍 Found user: ${user.userName}, Email: ${
              user.email
            }, Has SecurityPin: ${!!user.securityPin}`
          );
          break; // Email is unique, so we can break after finding the user
        }
      } catch (err) {
        // Skip collections that might not be user collections
        continue;
      }
    }

    if (!foundUser) {
      console.log(`❌ No user found with email: ${email}`);
      return res
        .status(404)
        .json({ error: "No account found with this email address." });
    }

    // Return security PIN status
    res.status(200).json({
      hasSecurityPin: !!foundUser.securityPin,
      message: foundUser.securityPin
        ? "User has a security PIN set"
        : "User does not have a security PIN",
    });
  } catch (error) {
    console.error("❌ Error checking security PIN:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📧 **Google Authentication Route**
app.post("/api/google-auth", async (req, res) => {
  console.log("🔐 Google auth route hit!");
  const { googleId, email, name, picture } = req.body;

  try {
    if (!googleId || !email || !name) {
      return res
        .status(400)
        .json({ error: "Missing required Google authentication data." });
    }

    // Check if user exists by email across all collections
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    let foundUser = null;
    let userModel = null;

    for (const collection of collections) {
      const collectionName = collection.name;

      // Skip system collections
      if (collectionName.startsWith("system.")) continue;

      try {
        const UserModel = createUserModel(collectionName);
        const user = await UserModel.findOne({ email });

        if (user) {
          foundUser = user;
          userModel = UserModel;
          break;
        }
      } catch (err) {
        // Skip collections that might not be user collections
        continue;
      }
    }

    if (foundUser) {
      // User exists, log them in
      const payload = {
        id: foundUser._id,
        userName: foundUser.userName,
      };

      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

      console.log(
        "✅ Google login successful for existing user:",
        foundUser.userName
      );
      return res.status(200).json({
        message: "Google login successful!",
        token,
        user: {
          firstName: foundUser.firstName,
          lastName: foundUser.lastName,
          username: foundUser.userName,
          email: foundUser.email,
          age: foundUser.age,
          retirementAge: foundUser.retirementAge,
          phoneNumber: foundUser.phoneNumber,
          country: foundUser.country,
        },
      });
    } else {
      // User doesn't exist, need to create account
      // For Google auth, we'll need some default values
      const nameParts = name.split(" ");
      const firstName = nameParts[0] || name;
      const lastName = nameParts.slice(1).join(" ") || "";

      // Generate username from email
      const baseUsername = email
        .split("@")[0]
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");
      let userName = baseUsername;

      // Make sure username is unique
      let counter = 1;
      while (true) {
        const collections = await mongoose.connection.db
          .listCollections()
          .toArray();
        const existingCollection = collections.some(
          (col) => col.name === userName
        );

        if (!existingCollection) break;

        userName = `${baseUsername}${counter}`;
        counter++;
      }

      // Create new user with Google data
      const UserModel = createUserModel(userName);
      const newUser = new UserModel({
        firstName,
        lastName,
        userName,
        email,
        password: await bcrypt.hash(googleId, 10), // Use googleId as password (they'll use Google login)
        age: 25, // Default age
        retirementAge: 65, // Default retirement age
        phoneNumber: "", // Empty for now
        country: "Unknown", // Default country
      });

      await newUser.save();

      const payload = {
        id: newUser._id,
        userName: newUser.userName,
      };

      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

      console.log(
        "✅ Google signup successful for new user:",
        newUser.userName
      );
      return res.status(201).json({
        message: "Google signup successful!",
        token,
        user: {
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          username: newUser.userName,
          email: newUser.email,
          age: newUser.age,
          retirementAge: newUser.retirementAge,
          phoneNumber: newUser.phoneNumber,
          country: newUser.country,
        },
      });
    }
  } catch (error) {
    console.error("❌ Error in Google authentication:", error);
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

// 📌 **Add Security PIN to Existing User (Temporary Migration Endpoint)**
app.post("/api/add-security-pin", async (req, res) => {
  console.log("🔐 Add security PIN route hit!");
  const { email, securityPin } = req.body;

  try {
    // Input validation
    if (!email || !securityPin) {
      return res.status(400).json({
        error: "Email and security PIN are required.",
      });
    }

    // Find user by email across all collections
    let foundUser = null;
    let userModel = null;

    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();

    for (const collection of collections) {
      const collectionName = collection.name;

      // Skip system collections
      if (collectionName.startsWith("system.")) continue;

      try {
        const UserModel = createUserModel(collectionName);
        const user = await UserModel.findOne({ email: email });

        if (user) {
          foundUser = user;
          userModel = UserModel;
          console.log(`🔍 Found user: ${user.userName}, Email: ${user.email}`);
          break;
        }
      } catch (err) {
        // Skip collections that might not be user collections
        continue;
      }
    }

    if (!foundUser) {
      console.log(`❌ No user found with email: ${email}`);
      return res
        .status(404)
        .json({ error: "No account found with this email address." });
    }

    // Check if user already has a security PIN
    if (foundUser.securityPin) {
      console.log(
        `⚠️ User ${foundUser.userName} (${email}) already has a security PIN`
      );
      return res.status(400).json({
        error: "This account already has a security PIN set.",
      });
    }

    // Hash the security PIN with enhanced security (12 rounds)
    const saltRounds = 12;
    const hashedSecurityPin = await bcrypt.hash(securityPin, saltRounds);

    // Update user with security PIN
    await userModel.findByIdAndUpdate(foundUser._id, {
      securityPin: hashedSecurityPin,
    });

    console.log(`✅ Security setup completed for user: ${foundUser.userName}`);

    res.status(200).json({
      message:
        "Security setup completed successfully! You can now use the password reset feature.",
    });
  } catch (error) {
    console.error("❌ Error adding security PIN:", error);
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

// 🔹 **Manual Index Fix Endpoint**
app.post("/fix-stock-indexes", async (req, res) => {
  try {
    console.log("🔧 Manual index fix requested");

    // More aggressive index cleanup
    try {
      const collection = StockPortfolio.collection;
      const indexes = await collection.getIndexes();
      console.log("📋 All indexes before cleanup:", Object.keys(indexes));

      // Drop ALL indexes except _id (which can't be dropped)
      for (const indexName of Object.keys(indexes)) {
        if (indexName !== "_id_") {
          try {
            await collection.dropIndex(indexName);
            console.log(`✅ Dropped index: ${indexName}`);
          } catch (dropError) {
            console.log(`⚠️ Could not drop ${indexName}:`, dropError.message);
          }
        }
      }

      // Recreate only the indexes we need
      await collection.createIndex(
        { userName: 1, symbol: 1, dateAdded: -1 },
        { background: true }
      );
      console.log("✅ Created compound index: userName + symbol + dateAdded");

      await collection.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0, background: true }
      );
      console.log("✅ Created TTL index for auto-deletion");
    } catch (aggressiveError) {
      console.log("⚠️ Aggressive cleanup error:", aggressiveError.message);
    }

    await fixStockPortfolioIndexes();
    res.json({
      success: true,
      message: "Stock portfolio indexes have been aggressively fixed",
    });
  } catch (error) {
    console.error("❌ Error fixing indexes:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
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

// --- NAV Fetching and Mutual Fund API ---

/**
 * Fetches NAV data from AMFI and updates the database efficiently.
 * This function now uses bulkWrite for a massive performance improvement.
 */
const fetchAndStoreNAVData = async () => {
  try {
    console.log("📈 Fetching NAV data from AMFI...");

    const response = await axios.get(
      "https://www.amfiindia.com/spages/NAVAll.txt",
      {
        timeout: 60000, // 60 second timeout
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; NAVFetcher/1.0)",
        },
      }
    );

    console.log(
      `📊 Received response size: ${response.data.length} characters`
    );

    const lines = response.data.split("\n");
    console.log(`📊 Total lines in response: ${lines.length}`);

    const updates = [];
    let validLines = 0;
    let invalidLines = 0;

    for (const line of lines) {
      if (
        line.trim() === "" ||
        line.includes("Scheme Code") ||
        line.includes("ISIN") ||
        line.includes("Open Ended") ||
        line.includes("Mutual Fund") ||
        line.startsWith("Close")
      ) {
        continue;
      }

      const parts = line.split(";");
      if (parts.length >= 2) {
        // Further reduced - accept any line with at least 2 parts
        // Extract data with fallbacks
        const schemeCode =
          (parts[0] ? parts[0].trim() : "") || `AUTO_${validLines + 1}`;
        const schemeName =
          (parts[3] ? parts[3].trim() : "") ||
          (parts[1] ? parts[1].trim() : "") ||
          `Fund ${validLines + 1}`;
        const navString = parts[4] ? parts[4].trim() : "0";
        const nav = parseFloat(navString) || 0;

        // Accept ALL lines with any meaningful data - no validation filtering
        const finalSchemeCode = schemeCode;
        const finalSchemeName = schemeName;

        updates.push({
          updateOne: {
            filter: { schemeCode: finalSchemeCode },
            update: {
              $set: {
                schemeCode: finalSchemeCode,
                schemeName: finalSchemeName,
                nav: nav,
                lastUpdated: new Date(),
              },
            },
            upsert: true,
          },
        });
        validLines++;
      } else {
        // Only reject lines with less than 2 parts
        invalidLines++;
        if (invalidLines <= 5) {
          console.log(
            `⚠️ Invalid line (insufficient parts): ${line.substring(0, 100)}...`
          );
        }
      }
    }

    console.log(`📊 Processing statistics:
    - Total lines: ${lines.length}
    - Valid funds: ${validLines}
    - Invalid lines: ${invalidLines}
    - Updates to process: ${updates.length}`);

    if (updates.length > 0) {
      console.log("💾 Starting bulk write to database...");
      const result = await MutualFund.bulkWrite(updates, { ordered: false });
      console.log(`✅ NAV data updated successfully. 
      - Processed: ${updates.length} funds
      - Inserted: ${result.upsertedCount}
      - Modified: ${result.modifiedCount}
      - Total operations: ${
        result.insertedCount + result.modifiedCount + result.upsertedCount
      }`);

      // Get final count
      const totalCount = await MutualFund.countDocuments();
      console.log(`📊 Total funds in database: ${totalCount}`);
    } else {
      console.log("ℹ️ No new NAV data to update.");
    }
  } catch (error) {
    console.error("❌ Error fetching NAV data:", error.message);
    if (error.response) {
      console.error("Response status:", error.response.status);
      console.error("Response headers:", error.response.headers);
    }
    throw error;
  }
};

// Schedule daily NAV update at 9:15 PM India Time
cron.schedule("15 21 * * *", fetchAndStoreNAVData, {
  timezone: "Asia/Kolkata",
});
// Initial fetch on server start
fetchAndStoreNAVData();

// --- Mutual Fund API Endpoints ---

/**
 * NEW: Get all mutual funds grouped by company.
 * Supports server-side search by company name.
 */
app.get("/mutualfunds/companies", async (req, res) => {
  try {
    const search = req.query.search || "";
    console.log(`🔍 Fetching companies endpoint with search: "${search}"`);

    // First, get all mutual funds
    const allFunds = await MutualFund.find(
      {},
      {
        schemeCode: 1,
        schemeName: 1,
        nav: 1,
        lastUpdated: 1,
        fundHouse: 1,
        date: 1,
      }
    );

    console.log(`📊 Retrieved ${allFunds.length} total funds from database`);

    // Remove duplicates by keeping only the most recent entry for each scheme code
    const uniqueFundsMap = new Map();

    allFunds.forEach((fund) => {
      const existingFund = uniqueFundsMap.get(fund.schemeCode);
      if (
        !existingFund ||
        new Date(fund.lastUpdated || fund.date) >
          new Date(existingFund.lastUpdated || existingFund.date)
      ) {
        uniqueFundsMap.set(fund.schemeCode, fund);
      }
    });

    const uniqueFunds = Array.from(uniqueFundsMap.values());
    console.log(`📊 After deduplication: ${uniqueFunds.length} unique funds`);

    // Filter out invalid/malformed funds with stricter validation
    const validFunds = uniqueFunds.filter((fund) => {
      // Remove funds with invalid scheme names
      const isValidSchemeName =
        fund.schemeName &&
        typeof fund.schemeName === "string" &&
        fund.schemeName.trim().length > 5 &&
        fund.schemeName.trim() !== "-" &&
        fund.schemeName.trim() !== "N/A" &&
        fund.schemeName.trim() !== "null" &&
        fund.schemeName.trim() !== "undefined" &&
        !fund.schemeName.includes("_L") &&
        !fund.schemeName.startsWith("119") &&
        !fund.schemeName.match(/^\d+_/) &&
        fund.schemeName.includes(" ");

      // Remove funds with invalid scheme codes
      const isValidSchemeCode =
        fund.schemeCode &&
        typeof fund.schemeCode === "string" &&
        fund.schemeCode.trim().length > 0 &&
        !fund.schemeCode.includes("_L") &&
        fund.schemeCode.length <= 10;

      // Must have valid NAV
      const isValidNAV =
        fund.nav &&
        (typeof fund.nav === "number"
          ? fund.nav > 0
          : parseFloat(fund.nav) > 0);

      return isValidSchemeName && isValidSchemeCode && isValidNAV;
    });

    console.log(
      `📊 After validation: ${validFunds.length} valid funds (removed ${
        uniqueFunds.length - validFunds.length
      } invalid funds)`
    );

    // Function to extract company name from scheme name
    const extractCompanyName = (schemeName) => {
      if (!schemeName || typeof schemeName !== "string") {
        return "OTHERS";
      }

      // Common company name patterns in Indian mutual funds
      const commonCompanies = [
        "ADITYA BIRLA SUN LIFE",
        "AXIS",
        "BAJAJ FINSERV",
        "BANDHAN",
        "BARODA BNP PARIBAS",
        "BOI AXA",
        "CANARA ROBECO",
        "DSP",
        "EDELWEISS",
        "FRANKLIN TEMPLETON",
        "HDFC",
        "ICICI PRUDENTIAL",
        "IDBI",
        "IDFC",
        "INVESCO",
        "ITI",
        "KOTAK",
        "L&T",
        "LIC",
        "MAHINDRA",
        "MIRAE ASSET",
        "MOTILAL OSWAL",
        "NIPPON INDIA",
        "PARAG PARIKH",
        "PGIM",
        "QUANTUM",
        "QUANT",
        "RELIANCE",
        "SAHARA",
        "SBI",
        "SHRIRAM",
        "SUNDARAM",
        "TATA",
        "UNION",
        "UTI",
        "YES FUND",
        "360 ONE",
        "GROWW",
        "ZERODHA",
        "NAVI",
      ];

      const upperSchemeName = schemeName.toUpperCase();

      // Try to match known company names first
      for (const company of commonCompanies) {
        if (upperSchemeName.startsWith(company)) {
          return company;
        }
      }

      // Fallback: Extract first few words as company name
      // Remove common fund-related words and extract meaningful company name
      let companyName = schemeName
        .replace(
          /\s+(MUTUAL\s+FUND|FUND|SCHEME|PLAN|DIRECT|REGULAR|GROWTH|DIVIDEND|IDCW)\b/gi,
          " "
        )
        .trim();

      // Take first 2-3 words as company name
      const words = companyName.split(/\s+/);
      companyName = words.slice(0, Math.min(3, words.length)).join(" ");

      return companyName.toUpperCase() || "OTHERS";
    };

    // Group funds by company using validFunds
    const companiesMap = new Map();

    validFunds.forEach((fund) => {
      try {
        const companyName = extractCompanyName(fund.schemeName);

        if (!companiesMap.has(companyName)) {
          companiesMap.set(companyName, {
            companyName: companyName,
            fundCount: 0,
            schemes: [],
            lastUpdated:
              fund.lastUpdated || fund.date || new Date().toISOString(),
          });
        }

        const company = companiesMap.get(companyName);
        company.fundCount++;
        company.schemes.push({
          schemeCode: fund.schemeCode,
          schemeName: fund.schemeName,
          nav: fund.nav,
          lastUpdated:
            fund.lastUpdated || fund.date || new Date().toISOString(),
        });

        // Update last updated date
        const fundDate = new Date(fund.lastUpdated || fund.date);
        const companyDate = new Date(company.lastUpdated);
        if (fundDate > companyDate) {
          company.lastUpdated = fund.lastUpdated || fund.date;
        }
      } catch (error) {
        console.error("Error processing fund:", fund, error);
      }
    });

    // Convert Map to Array and apply search filter
    let companies = Array.from(companiesMap.values());

    if (search && search.trim() !== "") {
      companies = companies.filter((company) =>
        company.companyName.toLowerCase().includes(search.toLowerCase())
      );
    }

    // Sort by company name and sort schemes within each company alphabetically
    companies.sort((a, b) => a.companyName.localeCompare(b.companyName));

    // Sort schemes within each company alphabetically
    companies.forEach((company) => {
      if (company.schemes && Array.isArray(company.schemes)) {
        company.schemes.sort((a, b) =>
          a.schemeName.localeCompare(b.schemeName)
        );
      }
    });

    const totalSchemes = companies.reduce(
      (sum, company) => sum + (company.schemes ? company.schemes.length : 0),
      0
    );

    console.log(
      `📊 Found ${companies.length} unique companies from ${validFunds.length} valid funds (${allFunds.length} total in DB)`
    );
    console.log(`📊 Total schemes across all companies: ${totalSchemes}`);
    console.log(
      `📊 Sample companies: ${companies
        .slice(0, 3)
        .map((c) => `${c.companyName} (${c.fundCount} funds)`)
        .join(", ")}`
    );

    res.json(companies);
  } catch (err) {
    console.error("❌ Error fetching companies:", err);
    console.error("❌ Error stack:", err.stack);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get a paginated list of all mutual funds.
 * Supports server-side search by scheme name.
 */
app.get("/mutualfunds", async (req, res) => {
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
      funds,
      totalPages: Math.ceil(totalFunds / limit),
      currentPage: page,
      totalFunds,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get details for a single mutual fund by its scheme code.
 */
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

/**
 * Manually trigger the NAV update process.
 */
app.post("/update-nav", async (req, res) => {
  try {
    console.log("🔄 Manual NAV update triggered...");
    await fetchAndStoreNAVData();

    // Get count after update
    const totalCount = await MutualFund.countDocuments();
    console.log(`📊 Total funds in database after update: ${totalCount}`);

    res.json({
      message: "NAV data updated successfully",
      totalFunds: totalCount,
    });
  } catch (error) {
    console.error("❌ Manual NAV update failed:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Test endpoint to check NAV parsing without updating database
 */
app.get("/test-nav-parsing", async (req, res) => {
  try {
    console.log("🧪 Testing NAV parsing...");

    const response = await axios.get(
      "https://www.amfiindia.com/spages/NAVAll.txt",
      {
        timeout: 60000,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; NAVFetcher/1.0)",
        },
      }
    );

    const lines = response.data.split("\n");
    console.log(`📊 Total lines in response: ${lines.length}`);

    let validLines = 0;
    let invalidLines = 0;
    let sampleValidLines = [];
    let sampleInvalidLines = [];

    for (const line of lines) {
      if (
        line.trim() === "" ||
        line.includes("Scheme Code") ||
        line.includes("ISIN") ||
        line.includes("Open Ended") ||
        line.includes("Mutual Fund") ||
        line.startsWith("Close")
      ) {
        continue;
      }

      const parts = line.split(";");
      if (parts.length >= 2) {
        // Further reduced - accept any line with at least 2 parts
        // Extract data with fallbacks
        const schemeCode =
          (parts[0] ? parts[0].trim() : "") || `AUTO_${validLines + 1}`;
        const schemeName =
          (parts[3] ? parts[3].trim() : "") ||
          (parts[1] ? parts[1].trim() : "") ||
          `Fund ${validLines + 1}`;
        const navString = parts[4] ? parts[4].trim() : "0";
        const nav = parseFloat(navString) || 0;

        // Accept ALL lines with any meaningful data
        validLines++;
        if (sampleValidLines.length < 3) {
          sampleValidLines.push({
            schemeCode: schemeCode,
            schemeName: schemeName.substring(0, 50) + "...",
            nav: nav,
          });
        }
      } else {
        // Only reject lines with less than 2 parts
        invalidLines++;
        if (sampleInvalidLines.length < 3) {
          sampleInvalidLines.push({
            line: line.substring(0, 100) + "...",
            parts: parts.length,
            reason: "insufficient_parts",
          });
        }
      }
    }

    res.json({
      totalLines: lines.length,
      validLines,
      invalidLines,
      sampleValidLines,
      sampleInvalidLines,
      message: `Found ${validLines} valid funds out of ${lines.length} lines`,
    });
  } catch (error) {
    console.error("❌ Error testing NAV parsing:", error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get database statistics for debugging
 */
app.get("/mf-stats", async (req, res) => {
  try {
    const totalFunds = await MutualFund.countDocuments();
    const sampleFunds = await MutualFund.find().limit(5);
    const lastUpdated = await MutualFund.findOne().sort({ lastUpdated: -1 });

    res.json({
      totalFunds,
      sampleFunds,
      lastUpdated: lastUpdated?.lastUpdated,
      message: `Database contains ${totalFunds} mutual funds`,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- Investment API Endpoints ---

/**
 * Get all investments for a user
 */
app.get("/investments", verifyToken, async (req, res) => {
  try {
    console.log("📊 Getting investments for user:", req.user.userName);
    console.log("📊 User object:", req.user);

    const userName = req.user.userName;
    const investments = await Investment.find({ userName: userName });
    console.log("📊 Found investments:", investments.length);

    res.json(investments);
  } catch (err) {
    console.error("❌ Error fetching investments:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Create a new investment
 */
app.post("/investment", verifyToken, async (req, res) => {
  try {
    console.log("💰 Creating investment for user:", req.user.userName);
    console.log("💰 Received Investment data:", req.body);

    const {
      name,
      amount,
      interestRate,
      investmentType,
      maturityDate,
      description,
      goalId,
      compoundingFrequency,
      monthlyDeposit,
      duration,
      // MF specific fields
      schemeCode,
      schemeName,
      units,
      nav,
      currentNAV,
      averageNAV,
      sipDate,
      calculationType,
      investmentDate,
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

    // Additional validation for Mutual Fund investments
    if (investmentType === "Mutual Fund") {
      if (!schemeCode || !schemeName || !units || !nav) {
        return res.status(400).json({
          error:
            "Missing required Mutual Fund fields: schemeCode, schemeName, units, nav",
        });
      }
    }

    const investmentData = {
      name,
      amount: parseFloat(amount),
      currentAmount: parseFloat(amount),
      interestRate: parseFloat(interestRate),
      investmentType,
      startDate: investmentDate ? new Date(investmentDate) : new Date(),
      maturityDate,
      description,
      goalId,
      compoundingFrequency,
      monthlyDeposit,
      duration,
      userName: req.user.userName,
    };

    // Add MF specific fields if it's a Mutual Fund investment
    if (investmentType === "Mutual Fund") {
      investmentData.schemeCode = schemeCode;
      investmentData.schemeName = schemeName;
      investmentData.units = parseFloat(units);
      investmentData.nav = parseFloat(nav);
      investmentData.currentNAV = parseFloat(currentNAV) || parseFloat(nav);
      investmentData.averageNAV = parseFloat(averageNAV) || parseFloat(nav);
      investmentData.sipDate = sipDate ? parseInt(sipDate) : null;
      investmentData.calculationType = calculationType;
      investmentData.investmentDate = investmentDate
        ? new Date(investmentDate)
        : new Date();

      // Calculate current amount for MF based on units and current NAV
      if (investmentData.units && investmentData.currentNAV) {
        investmentData.currentAmount =
          investmentData.units * investmentData.currentNAV;
      }
    }

    const newInvestment = new Investment(investmentData);

    await newInvestment.save();

    console.log("✅ Investment created successfully:", newInvestment._id);
    res.status(201).json(newInvestment);
  } catch (err) {
    console.error("❌ Error creating investment:", err);
    res.status(500).json({ error: err.message || "Failed to add investment" });
  }
});

/**
 * Update an investment
 */
app.put("/investment/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const investment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
    });

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

/**
 * Delete an investment
 */
app.delete("/investment/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const investment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
    });

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

// --- Mutual Fund Investment CRUD Operations ---

/**
 * Get all MF investments for a user
 */
app.get("/api/mf-investments", verifyToken, async (req, res) => {
  try {
    console.log("📈 Getting MF investments for user:", req.user.userName);

    const userName = req.user.userName;
    const mfInvestments = await Investment.find({
      userName: userName,
      investmentType: "Mutual Fund",
    }).sort({ startDate: -1 });

    console.log("📈 Found MF investments:", mfInvestments.length);
    res.json(mfInvestments);
  } catch (err) {
    console.error("❌ Error fetching MF investments:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Create a new MF investment
 */

// NEW: Fetch stock companies from Yahoo Finance via RapidAPI

/**
 * Delete an MF investment
 */
app.delete("/api/mf-investments/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const mfInvestment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
      investmentType: "Mutual Fund",
    });

    if (!mfInvestment) {
      return res
        .status(404)
        .json({ error: "MF Investment not found or not authorized" });
    }

    await Investment.findByIdAndDelete(req.params.id);
    console.log("✅ MF Investment deleted successfully:", req.params.id);
    res.json({ message: "MF Investment deleted successfully" });
  } catch (err) {
    console.error("❌ Error deleting MF investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get MF investment by scheme code for a user
 */
app.get("/mf-investment/scheme/:schemeCode", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const { schemeCode } = req.params;

    const mfInvestment = await Investment.findOne({
      userName: userName,
      schemeCode: schemeCode,
      investmentType: "Mutual Fund",
    });

    if (!mfInvestment) {
      return res.status(404).json({ error: "MF Investment not found" });
    }

    res.json(mfInvestment);
  } catch (err) {
    console.error("❌ Error fetching MF investment by scheme code:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Update NAV values for all MF investments
 */
app.post("/mf-investments/update-nav", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;

    // Get all MF investments for the user
    const mfInvestments = await Investment.find({
      userName: userName,
      investmentType: "Mutual Fund",
    });

    const updatePromises = mfInvestments.map(async (investment) => {
      if (investment.schemeCode) {
        try {
          // Find the latest NAV for this scheme
          const fund = await MutualFund.findOne({
            schemeCode: investment.schemeCode,
          });

          if (fund && fund.nav) {
            const newCurrentAmount = investment.units * parseFloat(fund.nav);

            await Investment.findByIdAndUpdate(investment._id, {
              currentNAV: parseFloat(fund.nav),
              currentAmount: newCurrentAmount,
              lastInterestUpdate: new Date(),
            });

            return {
              schemeCode: investment.schemeCode,
              schemeName: investment.schemeName,
              updatedNAV: fund.nav,
              updatedAmount: newCurrentAmount,
            };
          }
        } catch (err) {
          console.error(
            `❌ Error updating NAV for ${investment.schemeCode}:`,
            err
          );
          return null;
        }
      }
      return null;
    });

    const results = await Promise.all(updatePromises);
    const successfulUpdates = results.filter((result) => result !== null);

    console.log(
      `✅ Updated NAV for ${successfulUpdates.length} MF investments`
    );
    res.json({
      message: `Successfully updated NAV for ${successfulUpdates.length} investments`,
      updates: successfulUpdates,
    });
  } catch (err) {
    console.error("❌ Error updating MF investment NAVs:", err);
    res.status(500).json({ error: err.message });
  }
});

// ...existing code...

/**
 * Format company name from symbol (basic implementation)
 */
const formatCompanyName = (symbol) => {
  // Basic mapping for common symbols - this can be expanded
  const nameMap = {
    RELIANCE: "Reliance Industries Limited",
    TCS: "Tata Consultancy Services Limited",
    HDFCBANK: "HDFC Bank Limited",
    ICICIBANK: "ICICI Bank Limited",
    HINDUNILVR: "Hindustan Unilever Limited",
    INFY: "Infosys Limited",
    ITC: "ITC Limited",
    SBIN: "State Bank of India",
    BHARTIARTL: "Bharti Airtel Limited",
    KOTAKBANK: "Kotak Mahindra Bank Limited",
    LT: "Larsen & Toubro Limited",
    BAJFINANCE: "Bajaj Finance Limited",
    ASIANPAINT: "Asian Paints Limited",
    MARUTI: "Maruti Suzuki India Limited",
    HCLTECH: "HCL Technologies Limited",
    AXISBANK: "Axis Bank Limited",
    WIPRO: "Wipro Limited",
    ONGC: "Oil and Natural Gas Corporation Limited",
    TECHM: "Tech Mahindra Limited",
    TITAN: "Titan Company Limited",
    NESTLEIND: "Nestle India Limited",
    POWERGRID: "Power Grid Corporation of India Limited",
    NTPC: "NTPC Limited",
    ULTRACEMCO: "UltraTech Cement Limited",
    JSWSTEEL: "JSW Steel Limited",
    SUNPHARMA: "Sun Pharmaceutical Industries Limited",
    BAJAJFINSV: "Bajaj Finserv Limited",
    DRREDDY: "Dr. Reddy's Laboratories Limited",
    TATAMOTORS: "Tata Motors Limited",
    CIPLA: "Cipla Limited",
    EICHERMOT: "Eicher Motors Limited",
    GRASIM: "Grasim Industries Limited",
    HEROMOTOCO: "Hero MotoCorp Limited",
    COALINDIA: "Coal India Limited",
    BPCL: "Bharat Petroleum Corporation Limited",
    TATASTEEL: "Tata Steel Limited",
    BRITANNIA: "Britannia Industries Limited",
    DIVISLAB: "Divi's Laboratories Limited",
    ADANIPORTS: "Adani Ports and Special Economic Zone Limited",
    SHREECEM: "Shree Cement Limited",
    VEDL: "Vedanta Limited",
    APOLLOHOSP: "Apollo Hospitals Enterprise Limited",
    HINDALCO: "Hindalco Industries Limited",
    INDUSINDBK: "IndusInd Bank Limited",
    UPL: "UPL Limited",
    TATACONSUM: "Tata Consumer Products Limited",
    ADANIENT: "Adani Enterprises Limited",
    GODREJCP: "Godrej Consumer Products Limited",
    SBILIFE: "SBI Life Insurance Company Limited",
    PIDILITIND: "Pidilite Industries Limited",
    HDFCLIFE: "HDFC Life Insurance Company Limited",
  };

  return nameMap[symbol] || `${symbol} Limited`;
};

// � **Setup Stock Service**
stockService.setupStockRoutes(app);
stockService.initializeStockService();

// 🔹 **STOCK PORTFOLIO CRUD ENDPOINTS WITH AUTO-DELETE**

/**
 * Create a new stock entry in user's portfolio - auto-deletes after 1 week
 */
app.post("/api/stock-investments", verifyToken, async (req, res) => {
  try {
    console.log("📈 Processing stock transaction:", req.body);

    const {
      userName,
      symbol,
      name,
      exchange,
      quantity,
      purchasePrice,
      currentPrice,
      investmentType,
      notes,
    } = req.body;

    // Validation
    if (
      !userName ||
      !symbol ||
      !name ||
      !exchange ||
      quantity === undefined ||
      purchasePrice === undefined
    ) {
      console.error("❌ Missing required fields:", {
        userName,
        symbol,
        name,
        exchange,
        quantity,
        purchasePrice,
      });
      return res.status(400).json({
        error:
          "Missing required fields: userName, symbol, name, exchange, quantity, purchasePrice",
        received: { userName, symbol, name, exchange, quantity, purchasePrice },
      });
    }

    const quantityNum = parseFloat(quantity);
    const priceNum = parseFloat(purchasePrice);

    if (isNaN(quantityNum) || isNaN(priceNum)) {
      console.error("❌ Invalid numeric values:", { quantity, purchasePrice });
      return res.status(400).json({
        error: "Invalid numeric values for quantity or price",
        received: { quantity, purchasePrice },
      });
    }

    // Always use unique userName to prevent duplicate key errors
    // This is a workaround until indexes are properly fixed
    const uniqueUserName = `${userName}_${Date.now()}_${Math.random()
      .toString(36)
      .substr(2, 9)}`;

    console.log(
      `🔧 Using unique userName: ${uniqueUserName} (original: ${userName})`
    );

    let savedStock;

    try {
      const stockEntry = new StockPortfolio({
        userName: uniqueUserName, // Use unique identifier
        originalUserName: userName, // Store original for reference
        symbol: symbol.toUpperCase(),
        name,
        exchange: exchange.toUpperCase(),
        quantity: quantityNum, // Can be positive (buy) or negative (sell)
        purchasePrice: priceNum,
        currentPrice: parseFloat(currentPrice) || 0,
        investmentType: investmentType || "stock",
        notes: notes || "",
        dateAdded: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      savedStock = await stockEntry.save();
      console.log("✅ Stock saved successfully with unique userName");
    } catch (saveError) {
      // Even with unique userName, if save fails, try once more with super unique ID
      console.error(
        "❌ Save failed even with unique userName:",
        saveError.message
      );

      try {
        const superUniqueUserName = `${userName}_${Date.now()}_${Math.random()
          .toString(36)
          .substr(2, 15)}`;
        console.log(
          `🔧 Retrying with super unique userName: ${superUniqueUserName}`
        );

        const retryStock = new StockPortfolio({
          userName: superUniqueUserName,
          originalUserName: userName,
          symbol: symbol.toUpperCase(),
          name,
          exchange: exchange.toUpperCase(),
          quantity: quantityNum,
          purchasePrice: priceNum,
          currentPrice: parseFloat(currentPrice) || 0,
          investmentType: investmentType || "stock",
          notes: notes || "",
          dateAdded: new Date(),
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        savedStock = await retryStock.save();
        console.log("✅ Saved successfully with super unique userName");
      } catch (finalError) {
        console.error("❌ All save attempts failed:", finalError.message);
        throw finalError;
      }
    }
    console.log(
      "✅ Stock transaction recorded successfully, expires in 1 week:",
      savedStock._id,
      `Quantity: ${quantityNum}, Price: ${priceNum}`
    );

    res.status(201).json({
      success: true,
      message: `Stock ${
        quantityNum > 0 ? "purchase" : "sale"
      } recorded successfully (auto-deletes in 1 week)`,
      stock: savedStock,
    });
  } catch (error) {
    console.error("❌ Error processing stock transaction:", error);
    console.error("❌ Error stack:", error.stack);

    // Handle MongoDB duplicate key error specifically
    if (error.code === 11000) {
      console.error(
        "❌ Duplicate key error detected - trying final workaround..."
      );

      try {
        // Final workaround: create a unique identifier by adding timestamp
        const uniqueId = `${userName}_${symbol.toUpperCase()}_${Date.now()}`;

        const stockEntry = new StockPortfolio({
          userName: uniqueId, // Use unique identifier to bypass constraint
          originalUserName: userName, // Store original userName in separate field
          symbol: symbol.toUpperCase(),
          name,
          exchange: exchange.toUpperCase(),
          quantity: quantityNum,
          purchasePrice: priceNum,
          currentPrice: parseFloat(currentPrice) || 0,
          investmentType: investmentType || "stock",
          notes: notes || "",
          dateAdded: new Date(),
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        const savedStock = await stockEntry.save();
        console.log("✅ Successfully worked around duplicate key constraint");

        return res.status(201).json({
          success: true,
          message: `Stock ${
            quantityNum > 0 ? "purchase" : "sale"
          } recorded successfully (auto-deletes in 1 week)`,
          stock: savedStock,
          workaround: "Used unique identifier to bypass database constraint",
        });
      } catch (finalError) {
        console.error("❌ Final workaround also failed:", finalError);

        return res.status(400).json({
          error: "Database configuration error: duplicate key constraint",
          message:
            "There's an incorrect unique index in the database. Please contact support.",
          mongoError: error.message,
          solution: "Database indexes need to be fixed by administrator",
        });
      }
    }

    res.status(500).json({
      error: "Failed to process transaction",
      message: error.message,
      details: error.stack,
      code: error.code,
    });
  }
});

/**
 * Get all stock entries for a user
 */
app.get("/api/stock-investments/:userName", verifyToken, async (req, res) => {
  try {
    const { userName } = req.params;
    console.log("📊 Getting stock portfolio for user:", userName);

    // Search for stocks using both userName and originalUserName (for workaround records)
    const stocks = await StockPortfolio.find({
      $or: [{ userName: userName }, { originalUserName: userName }],
    }).sort({
      dateAdded: -1,
    });
    console.log(`✅ Found ${stocks.length} stocks for user ${userName}`);

    res.json({
      success: true,
      stocks: stocks,
    });
  } catch (error) {
    console.error("❌ Error fetching stock portfolio:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Update a stock entry
 */
app.put(
  "/api/stock-investments/:userName/:stockId",
  verifyToken,
  async (req, res) => {
    try {
      const { userName, stockId } = req.params;
      const updateData = req.body;
      console.log(
        `✏️ Updating stock ${stockId} for user ${userName}:`,
        updateData
      );

      delete updateData.userName;
      delete updateData._id;

      if (updateData.quantity !== undefined)
        updateData.quantity = parseFloat(updateData.quantity);
      if (updateData.purchasePrice !== undefined)
        updateData.purchasePrice = parseFloat(updateData.purchasePrice);
      if (updateData.currentPrice !== undefined)
        updateData.currentPrice = parseFloat(updateData.currentPrice);

      const updatedStock = await StockPortfolio.findOneAndUpdate(
        { _id: stockId, userName: userName },
        updateData,
        { new: true, runValidators: true }
      );

      if (!updatedStock) {
        return res.status(404).json({
          success: false,
          error: "Stock not found in portfolio",
        });
      }

      console.log("✅ Stock updated successfully:", updatedStock._id);
      res.json({
        success: true,
        message: "Stock updated successfully",
        stock: updatedStock,
      });
    } catch (error) {
      console.error("❌ Error updating stock:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Delete a stock entry
 */
app.delete(
  "/api/stock-investments/:userName/:stockId",
  verifyToken,
  async (req, res) => {
    try {
      const { userName, stockId } = req.params;
      console.log(`🗑️ Deleting stock ${stockId} for user ${userName}`);

      const deletedStock = await StockPortfolio.findOneAndDelete({
        _id: stockId,
        userName: userName,
      });

      if (!deletedStock) {
        return res.status(404).json({
          success: false,
          error: "Stock not found in portfolio",
        });
      }

      console.log("✅ Stock deleted successfully:", deletedStock.symbol);
      res.json({
        success: true,
        message: "Stock removed from portfolio successfully",
        deletedStock: deletedStock,
      });
    } catch (error) {
      console.error("❌ Error deleting stock:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get portfolio summary for a user
 */
app.get(
  "/api/stock-portfolio-summary/:userName",
  verifyToken,
  async (req, res) => {
    try {
      const { userName } = req.params;
      console.log("📊 Getting portfolio summary for user:", userName);

      const stocks = await StockPortfolio.find({ userName });

      const summary = {
        totalStocks: stocks.length,
        totalInvestment: 0,
        currentValue: 0,
        totalGainLoss: 0,
        totalGainLossPercent: 0,
      };

      stocks.forEach((stock) => {
        const investment = stock.quantity * stock.purchasePrice;
        const currentValue =
          stock.quantity * (stock.currentPrice || stock.purchasePrice);

        summary.totalInvestment += investment;
        summary.currentValue += currentValue;
      });

      summary.totalGainLoss = summary.currentValue - summary.totalInvestment;
      summary.totalGainLossPercent =
        summary.totalInvestment > 0
          ? (summary.totalGainLoss / summary.totalInvestment) * 100
          : 0;

      console.log("✅ Portfolio summary calculated:", summary);
      res.json({
        success: true,
        summary: summary,
      });
    } catch (error) {
      console.error("❌ Error calculating portfolio summary:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

// 🔹 **Auto-cleanup cron job - runs daily at 2 AM to clean expired entries**
cron.schedule("0 2 * * *", async () => {
  try {
    console.log("🕐 Running daily cleanup of expired stock entries...");
    const result = await StockPortfolio.deleteMany({
      expiresAt: { $lt: new Date() },
    });
    console.log(
      `✅ Daily cleanup: Removed ${result.deletedCount} expired stock entries`
    );
  } catch (error) {
    console.error("❌ Error in daily cleanup:", error);
  }
});

// 🔹 **Start Server**
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(
    `📱 Mobile devices can connect at: http://192.168.30.236:${PORT}`
  );
  console.log(`💻 Local access: http://localhost:${PORT}`);
});
