require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"); //n
const axios = require("axios");
const yahooFinance = require("yahoo-finance2").default;
const cron = require("node-cron");
// const nodemailer = require("nodemailer"); // Removed - no longer needed
// const crypto = require("crypto"); // Removed - no longer needed
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

// � Define Stock Transaction Schema
const stockTransactionSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  symbol: { type: String, required: true }, // e.g., "AAPL"
  companyName: { type: String, required: true },
  type: { type: String, required: true, enum: ["buy", "sell"] },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true }, // Price per share
  total: { type: Number, required: true }, // Total transaction value
  date: { type: String, required: true }, // Date in YYYY-MM-DD format
  timestamp: { type: Date, default: Date.now },
});

const StockTransaction = mongoose.model(
  "StockTransaction",
  stockTransactionSchema
);

// �🔹 **Fix Goal Collection Indexes**
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

    // Create a hashed password and security PIN
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedSecurityPin = await bcrypt.hash(securityPin, 10);

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

// � **Forgot Password Route (Security PIN based)**
app.post("/api/forgot-password", async (req, res) => {
  console.log("🔐 Forgot password route hit!");
  const { email, securityPin, newPassword } = req.body;

  try {
    // Input validation
    if (!email || !securityPin || !newPassword) {
      return res.status(400).json({
        error: "Email, security PIN, and new password are required.",
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
        const user = await UserModel.findOne({ email: email });

        if (user) {
          foundUser = user;
          userModel = UserModel;
          console.log(
            `🔍 Found user: ${user.userName}, Email: ${
              user.email
            }, Has SecurityPin: ${!!user.securityPin}, SecurityPin Value: "${
              user.securityPin
            }", SecurityPin Type: ${typeof user.securityPin}`
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

    // Check if user has a security PIN set
    if (!foundUser.securityPin) {
      console.log(
        `⚠️ User ${foundUser.userName} (${email}) exists but has no security PIN. Updating with provided PIN...`
      );

      // Hash the provided security PIN and save it to the user
      const hashedSecurityPin = await bcrypt.hash(securityPin, 10);

      // Update user with security PIN
      await userModel.findByIdAndUpdate(foundUser._id, {
        securityPin: hashedSecurityPin,
      });

      console.log(
        `✅ Security PIN added for user: ${foundUser.userName} (${foundUser.email})`
      );

      // Continue with password reset process
      foundUser.securityPin = hashedSecurityPin; // Update local object
    }

    console.log(
      `✅ User ${foundUser.userName} found with security PIN. Proceeding with verification...`
    );

    // Verify security PIN
    const isPinValid = await bcrypt.compare(securityPin, foundUser.securityPin);
    if (!isPinValid) {
      return res.status(401).json({ error: "Invalid security PIN." });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await userModel.findByIdAndUpdate(foundUser._id, {
      password: hashedNewPassword,
    });

    console.log(
      `✅ Password reset successful for user: ${foundUser.userName} (${foundUser.email})`
    );

    res.status(200).json({
      message:
        "Password reset successful! You can now log in with your new password.",
    });
  } catch (error) {
    console.error("❌ Error in forgot password:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// �📧 **Google Authentication Route**
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

    // Hash the security PIN
    const hashedSecurityPin = await bcrypt.hash(securityPin, 10);

    // Update user with security PIN
    await userModel.findByIdAndUpdate(foundUser._id, {
      securityPin: hashedSecurityPin,
    });

    console.log(
      `✅ Security PIN added successfully for user: ${foundUser.userName} (${foundUser.email})`
    );

    res.status(200).json({
      message:
        "Security PIN added successfully! You can now use the forgot password feature.",
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
    let lineNumber = 0;

    for (const line of lines) {
      lineNumber++;
      
      // Only skip completely empty lines (no content at all)
      if (line.trim() === "") {
        invalidLines++;
        continue;
      }

      // Process EVERY line that has any content, including headers
      const parts = line.split(";");
      
      // Extract data with maximum fallbacks - be extremely liberal
      let schemeCode = "";
      let schemeName = "";
      let navString = "0";
      
      // Try to extract meaningful data from any position
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i] ? parts[i].trim() : "";
        if (part) {
          if (!schemeCode) schemeCode = part;
          if (!schemeName && part !== schemeCode) schemeName = part;
          if (!navString || navString === "0") {
            const numMatch = part.match(/[\d,.]+/);
            if (numMatch) navString = numMatch[0];
          }
        }
      }
      
      // Ensure unique scheme codes by including line number
      const uniqueSchemeCode = schemeCode ? `${schemeCode}_L${lineNumber}` : `LINE_${lineNumber}`;
      const finalSchemeName = schemeName || line.substring(0, 100) || `Fund Line ${lineNumber}`;
      
      const nav = parseFloat(navString.replace(/,/g, '')) || 0;

      // Accept EVERY line with any content - use unique scheme codes
      updates.push({
        updateOne: {
          filter: { schemeCode: uniqueSchemeCode },
          update: {
            $set: {
              schemeCode: uniqueSchemeCode,
              schemeName: finalSchemeName,
              nav: nav,
              lastUpdated: new Date(),
              lineNumber: lineNumber,
              originalLine: line.substring(0, 200) // Store original for debugging
            },
          },
          upsert: true,
        },
      });
      validLines++;
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

    // First, get all mutual funds
    const allFunds = await MutualFund.find(
      {},
      {
        schemeCode: 1,
        schemeName: 1,
        nav: 1,
        lastUpdated: 1,
      }
    );

    // Function to extract company name from scheme name
    const extractCompanyName = (schemeName) => {
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

      return companyName.toUpperCase();
    };

    // Group funds by company
    const companiesMap = new Map();

    allFunds.forEach((fund) => {
      const companyName = extractCompanyName(fund.schemeName);

      if (!companiesMap.has(companyName)) {
        companiesMap.set(companyName, {
          companyName: companyName,
          fundCount: 0,
          schemes: [],
          lastUpdated: fund.lastUpdated,
        });
      }

      const company = companiesMap.get(companyName);
      company.fundCount++;
      company.schemes.push({
        schemeCode: fund.schemeCode,
        schemeName: fund.schemeName,
        nav: fund.nav,
        lastUpdated: fund.lastUpdated,
      });

      // Update last updated date
      if (fund.lastUpdated > company.lastUpdated) {
        company.lastUpdated = fund.lastUpdated;
      }
    });

    // Convert Map to Array and apply search filter
    let companies = Array.from(companiesMap.values());

    if (search) {
      companies = companies.filter((company) =>
        company.companyName.toLowerCase().includes(search.toLowerCase())
      );
    }

    // Sort by company name
    companies.sort((a, b) => a.companyName.localeCompare(b.companyName));

    console.log(
      `📊 Found ${companies.length} unique companies from ${allFunds.length} funds`
    );
    console.log(
      `📊 Sample companies: ${companies
        .slice(0, 5)
        .map((c) => `${c.companyName} (${c.fundCount} funds)`)
        .join(", ")}`
    );

    res.json(companies);
  } catch (err) {
    console.error("❌ Error fetching companies:", err);
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
        // Accept any line with at least 2 parts
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
            nav,
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
app.get("/mf-investments", verifyToken, async (req, res) => {
  try {
    console.log("📊 Getting MF investments for user:", req.user.userName);

    const userName = req.user.userName;
    const mfInvestments = await Investment.find({
      userName: userName,
      investmentType: "Mutual Fund",
    });
    console.log("📊 Found MF investments:", mfInvestments.length);

    res.json(mfInvestments);
  } catch (err) {
    console.error("❌ Error fetching MF investments:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Create a new MF investment
 */

// Yahoo Finance RapidAPI configuration
const RAPIDAPI_KEY = "fbe23ee161mshf68a7a9cfe4c228p131e2ajsn7a5b10710643";
const RAPIDAPI_HOST = "yahoo-finance166.p.rapidapi.com";

const rapidApiConfig = {
  headers: {
    "X-RapidAPI-Key": RAPIDAPI_KEY,
    "X-RapidAPI-Host": RAPIDAPI_HOST,
  },
  timeout: 30000,
};

// Popular stock lists for India and Global markets
const INDIAN_STOCKS = [
  {
    symbol: "RELIANCE.NS",
    name: "Reliance Industries Limited",
    exchange: "NSE",
  },
  {
    symbol: "TCS.NS",
    name: "Tata Consultancy Services Limited",
    exchange: "NSE",
  },
  { symbol: "HDFCBANK.NS", name: "HDFC Bank Limited", exchange: "NSE" },
  { symbol: "ICICIBANK.NS", name: "ICICI Bank Limited", exchange: "NSE" },
  {
    symbol: "HINDUNILVR.NS",
    name: "Hindustan Unilever Limited",
    exchange: "NSE",
  },
  { symbol: "INFY.NS", name: "Infosys Limited", exchange: "NSE" },
  { symbol: "ITC.NS", name: "ITC Limited", exchange: "NSE" },
  { symbol: "SBIN.NS", name: "State Bank of India", exchange: "NSE" },
  { symbol: "BHARTIARTL.NS", name: "Bharti Airtel Limited", exchange: "NSE" },
  {
    symbol: "KOTAKBANK.NS",
    name: "Kotak Mahindra Bank Limited",
    exchange: "NSE",
  },
  // BSE equivalents
  {
    symbol: "RELIANCE.BO",
    name: "Reliance Industries Limited",
    exchange: "BSE",
  },
  {
    symbol: "TCS.BO",
    name: "Tata Consultancy Services Limited",
    exchange: "BSE",
  },
  { symbol: "HDFCBANK.BO", name: "HDFC Bank Limited", exchange: "BSE" },
  { symbol: "ICICIBANK.BO", name: "ICICI Bank Limited", exchange: "BSE" },
  {
    symbol: "HINDUNILVR.BO",
    name: "Hindustan Unilever Limited",
    exchange: "BSE",
  },
];

const GLOBAL_STOCKS = [
  // NASDAQ Tech Giants
  {
    symbol: "AAPL",
    name: "Apple Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MSFT",
    name: "Microsoft Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "GOOGL",
    name: "Alphabet Inc. Class A",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "GOOG",
    name: "Alphabet Inc. Class C",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "AMZN",
    name: "Amazon.com Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "TSLA",
    name: "Tesla Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "META",
    name: "Meta Platforms Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "NVDA",
    name: "NVIDIA Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "NFLX",
    name: "Netflix Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ADBE",
    name: "Adobe Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CRM",
    name: "Salesforce Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ORCL",
    name: "Oracle Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "INTC",
    name: "Intel Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "AMD",
    name: "Advanced Micro Devices Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "PYPL",
    name: "PayPal Holdings Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CMCSA",
    name: "Comcast Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "PEP",
    name: "PepsiCo Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "COST",
    name: "Costco Wholesale Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "AVGO",
    name: "Broadcom Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "TXN",
    name: "Texas Instruments Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "QCOM",
    name: "QUALCOMM Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "AMGN",
    name: "Amgen Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "SBUX",
    name: "Starbucks Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "GILD",
    name: "Gilead Sciences Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MDLZ",
    name: "Mondelez International Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ISRG",
    name: "Intuitive Surgical Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "REGN",
    name: "Regeneron Pharmaceuticals Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "VRTX",
    name: "Vertex Pharmaceuticals Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "FISV",
    name: "Fiserv Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },

  // NYSE Blue Chips
  {
    symbol: "JPM",
    name: "JPMorgan Chase & Co.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "JNJ",
    name: "Johnson & Johnson",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "V",
    name: "Visa Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "PG",
    name: "Procter & Gamble Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "UNH",
    name: "UnitedHealth Group Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "HD",
    name: "Home Depot Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MA",
    name: "Mastercard Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "BAC",
    name: "Bank of America Corp.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "DIS",
    name: "Walt Disney Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "XOM",
    name: "Exxon Mobil Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CVX",
    name: "Chevron Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "KO",
    name: "Coca-Cola Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "WMT",
    name: "Walmart Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MRK",
    name: "Merck & Co. Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "BRK.A",
    name: "Berkshire Hathaway Inc. Class A",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "BRK.B",
    name: "Berkshire Hathaway Inc. Class B",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "LLY",
    name: "Eli Lilly and Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "TMO",
    name: "Thermo Fisher Scientific Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ABT",
    name: "Abbott Laboratories",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ACN",
    name: "Accenture plc",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CVS",
    name: "CVS Health Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "DHR",
    name: "Danaher Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "VZ",
    name: "Verizon Communications Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "WFC",
    name: "Wells Fargo & Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "BMY",
    name: "Bristol-Myers Squibb Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "HON",
    name: "Honeywell International Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "UPS",
    name: "United Parcel Service Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "LOW",
    name: "Lowe's Companies Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "SPGI",
    name: "S&P Global Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "UNP",
    name: "Union Pacific Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CAT",
    name: "Caterpillar Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "GS",
    name: "Goldman Sachs Group Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MS",
    name: "Morgan Stanley",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "RTX",
    name: "Raytheon Technologies Corp.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "DE",
    name: "Deere & Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MMM",
    name: "3M Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "AXP",
    name: "American Express Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "IBM",
    name: "International Business Machines Corp.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CCI",
    name: "Crown Castle Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "TGT",
    name: "Target Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "CI",
    name: "Cigna Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "SO",
    name: "Southern Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ZTS",
    name: "Zoetis Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "BDX",
    name: "Becton Dickinson and Company",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "SYK",
    name: "Stryker Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ADP",
    name: "Automatic Data Processing Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "LRCX",
    name: "Lam Research Corporation",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "MU",
    name: "Micron Technology Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },
  {
    symbol: "ADI",
    name: "Analog Devices Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "United States",
    type: "Common Stock",
  },

  // International Companies (ADRs)
  {
    symbol: "TSM",
    name: "Taiwan Semiconductor Manufacturing Co. Ltd.",
    exchange: "NYSE",
    currency: "USD",
    country: "Taiwan",
    type: "ADR",
  },
  {
    symbol: "ASML",
    name: "ASML Holding N.V.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "Netherlands",
    type: "ADR",
  },
  {
    symbol: "SAP",
    name: "SAP SE",
    exchange: "NYSE",
    currency: "USD",
    country: "Germany",
    type: "ADR",
  },
  {
    symbol: "BABA",
    name: "Alibaba Group Holding Limited",
    exchange: "NYSE",
    currency: "USD",
    country: "China",
    type: "ADR",
  },
  {
    symbol: "NVO",
    name: "Novo Nordisk A/S",
    exchange: "NYSE",
    currency: "USD",
    country: "Denmark",
    type: "ADR",
  },
  {
    symbol: "NVS",
    name: "Novartis AG",
    exchange: "NYSE",
    currency: "USD",
    country: "Switzerland",
    type: "ADR",
  },
  {
    symbol: "TM",
    name: "Toyota Motor Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "Japan",
    type: "ADR",
  },
  {
    symbol: "UL",
    name: "Unilever PLC",
    exchange: "NYSE",
    currency: "USD",
    country: "United Kingdom",
    type: "ADR",
  },
  {
    symbol: "SNY",
    name: "Sanofi",
    exchange: "NASDAQ",
    currency: "USD",
    country: "France",
    type: "ADR",
  },
  {
    symbol: "SONY",
    name: "Sony Group Corporation",
    exchange: "NYSE",
    currency: "USD",
    country: "Japan",
    type: "ADR",
  },
  {
    symbol: "NTT",
    name: "Nippon Telegraph and Telephone Corp.",
    exchange: "NYSE",
    currency: "USD",
    country: "Japan",
    type: "ADR",
  },
  {
    symbol: "MUFG",
    name: "Mitsubishi UFJ Financial Group Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "Japan",
    type: "ADR",
  },
  {
    symbol: "SMFG",
    name: "Sumitomo Mitsui Financial Group Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "Japan",
    type: "ADR",
  },
  {
    symbol: "TD",
    name: "Toronto-Dominion Bank",
    exchange: "NYSE",
    currency: "USD",
    country: "Canada",
    type: "Common Stock",
  },
  {
    symbol: "RY",
    name: "Royal Bank of Canada",
    exchange: "NYSE",
    currency: "USD",
    country: "Canada",
    type: "Common Stock",
  },
  {
    symbol: "SHOP",
    name: "Shopify Inc.",
    exchange: "NYSE",
    currency: "USD",
    country: "Canada",
    type: "Common Stock",
  },
  {
    symbol: "BCS",
    name: "Barclays PLC",
    exchange: "NYSE",
    currency: "USD",
    country: "United Kingdom",
    type: "ADR",
  },
  {
    symbol: "BP",
    name: "BP plc",
    exchange: "NYSE",
    currency: "USD",
    country: "United Kingdom",
    type: "ADR",
  },
  {
    symbol: "SHELL",
    name: "Shell plc",
    exchange: "NYSE",
    currency: "USD",
    country: "United Kingdom",
    type: "ADR",
  },
  {
    symbol: "RIO",
    name: "Rio Tinto plc",
    exchange: "NYSE",
    currency: "USD",
    country: "United Kingdom",
    type: "ADR",
  },
  {
    symbol: "BHP",
    name: "BHP Group Limited",
    exchange: "NYSE",
    currency: "USD",
    country: "Australia",
    type: "ADR",
  },

  // Emerging Market Companies
  {
    symbol: "JD",
    name: "JD.com Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "China",
    type: "ADR",
  },
  {
    symbol: "PDD",
    name: "PDD Holdings Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "China",
    type: "ADR",
  },
  {
    symbol: "NTES",
    name: "NetEase Inc.",
    exchange: "NASDAQ",
    currency: "USD",
    country: "China",
    type: "ADR",
  },
  {
    symbol: "WIT",
    name: "Wipro Limited",
    exchange: "NYSE",
    currency: "USD",
    country: "India",
    type: "ADR",
  },
  {
    symbol: "IBN",
    name: "ICICI Bank Limited",
    exchange: "NYSE",
    currency: "USD",
    country: "India",
    type: "ADR",
  },
  {
    symbol: "HDB",
    name: "HDFC Bank Limited",
    exchange: "NYSE",
    currency: "USD",
    country: "India",
    type: "ADR",
  },
  {
    symbol: "VALE",
    name: "Vale S.A.",
    exchange: "NYSE",
    currency: "USD",
    country: "Brazil",
    type: "ADR",
  },
  {
    symbol: "ITUB",
    name: "Itaú Unibanco Holding S.A.",
    exchange: "NYSE",
    currency: "USD",
    country: "Brazil",
    type: "ADR",
  },
  {
    symbol: "PBR",
    name: "Petróleo Brasileiro S.A. - Petrobras",
    exchange: "NYSE",
    currency: "USD",
    country: "Brazil",
    type: "ADR",
  },
];

/**
 * Get stock companies from Yahoo Finance RapidAPI - DYNAMIC FETCHING
 */
app.get("/api/stock-companies", async (req, res) => {
  try {
    const {
      tab = "INDIA",
      exchange = "NSE",
      search = "",
      page = 1,
      limit = 100,
    } = req.query;

    console.log(
      `🔍 Fetching stocks dynamically for tab: ${tab}, exchange: ${exchange}, search: "${search}"`
    );

    let companies = [];
    let region = tab === "INDIA" ? "IN" : "US";

    // Strategy 1: If there's a search query, use search API
    if (search && search.trim()) {
      console.log(`🔍 Searching for "${search}" in region ${region}`);

      try {
        const searchUrl = `https://${RAPIDAPI_HOST}/api/autocomplete`;
        const searchResponse = await axios.get(searchUrl, {
          ...rapidApiConfig,
          params: {
            q: search.trim(),
            region: region,
          },
        });

        if (searchResponse.data && searchResponse.data.quotes) {
          const stockQuotes = searchResponse.data.quotes.filter(
            (quote) =>
              quote.typeDisp === "Equity" ||
              quote.quoteType === "EQUITY" ||
              quote.isYahooFinance === true
          );

          companies = stockQuotes.slice(0, parseInt(limit)).map((quote) => ({
            symbol: quote.symbol,
            name: quote.longname || quote.shortname || quote.symbol,
            exchange: quote.exchDisp || quote.exchange || "Unknown",
            type: "Common Stock",
            currency: tab === "INDIA" ? "INR" : "USD",
            country: tab === "INDIA" ? "India" : "United States",
            sector: quote.sector || "Unknown",
            industry: quote.industry || "Unknown",
          }));

          console.log(`📊 Search found ${companies.length} stocks`);
        }
      } catch (searchError) {
        console.error("❌ Search API error:", searchError.message);
      }
    }

    // Strategy 2: For India tab, fetch ALL stocks from BSE and NSE (7,500+ companies)
    if (tab === "INDIA" && (!search || !search.trim())) {
      console.log(
        `🇮🇳 Fetching ALL Indian stocks from ${exchange} (targeting 7,500+ companies)`
      );

      try {
        let allIndianStocks = [];

        // Fetch multiple pages/batches to get all stocks
        const batchSize = 500;
        const maxBatches = 20; // Should cover 10,000+ stocks

        for (let batch = 0; batch < maxBatches; batch++) {
          try {
            console.log(
              `🔄 Fetching batch ${batch + 1}/${maxBatches} for ${exchange}`
            );

            const screenerUrl = `https://${RAPIDAPI_HOST}/api/screener/list-by-predefined-screener`;
            const screenerResponse = await axios.get(screenerUrl, {
              ...rapidApiConfig,
              params: {
                screener_name: "most_actives", // Use a known working screener
                region: "IN",
                count: batchSize,
                offset: batch * batchSize,
              },
            });

            if (
              screenerResponse.data &&
              screenerResponse.data.finance &&
              screenerResponse.data.finance.result &&
              screenerResponse.data.finance.result[0] &&
              screenerResponse.data.finance.result[0].quotes
            ) {
              const quotes = screenerResponse.data.finance.result[0].quotes;

              if (quotes.length === 0) {
                console.log(
                  `📊 No more stocks found in batch ${batch + 1}, stopping`
                );
                break; // No more stocks
              }

              const batchStocks = quotes.map((quote) => ({
                symbol: quote.symbol,
                name: quote.longName || quote.shortName || quote.symbol,
                exchange: quote.fullExchangeName || quote.exchange || "Unknown",
                type: "Common Stock",
                currency: "INR",
                country: "India",
                currentPrice: quote.regularMarketPrice || 0,
                change: quote.regularMarketChange || 0,
                percentChange: quote.regularMarketChangePercent || 0,
                volume: quote.regularMarketVolume || 0,
                marketCap: quote.marketCap || 0,
                sector: quote.sector || "Unknown",
                industry: quote.industry || "Unknown",
              }));

              allIndianStocks = [...allIndianStocks, ...batchStocks];
              console.log(
                `📈 Batch ${batch + 1}: +${batchStocks.length} stocks (Total: ${
                  allIndianStocks.length
                })`
              );

              // Small delay to avoid rate limiting
              await new Promise((resolve) => setTimeout(resolve, 100));
            } else {
              console.log(
                `❌ Invalid response structure in batch ${batch + 1}`
              );
              break;
            }
          } catch (batchError) {
            console.error(
              `❌ Error in batch ${batch + 1}:`,
              batchError.message
            );
            break; // Stop if we hit an error
          }
        }

        // If the screener approach didn't work, try alternative approach
        if (allIndianStocks.length < 100) {
          console.log(
            "🔄 Screener didn't return enough stocks, trying alternative approaches..."
          );

          // Try getting stocks by searching common letters/terms
          const searchTerms = [
            "A",
            "B",
            "C",
            "D",
            "E",
            "F",
            "G",
            "H",
            "I",
            "J",
            "K",
            "L",
            "M",
            "N",
            "O",
            "P",
            "Q",
            "R",
            "S",
            "T",
            "U",
            "V",
            "W",
            "X",
            "Y",
            "Z",
          ];

          for (const term of searchTerms) {
            try {
              const searchUrl = `https://${RAPIDAPI_HOST}/api/autocomplete`;
              const searchResponse = await axios.get(searchUrl, {
                ...rapidApiConfig,
                params: {
                  q: term,
                  region: "IN",
                },
              });

              if (searchResponse.data && searchResponse.data.quotes) {
                const stockQuotes = searchResponse.data.quotes.filter(
                  (quote) =>
                    (quote.typeDisp === "Equity" ||
                      quote.quoteType === "EQUITY") &&
                    (quote.symbol.includes(".NS") ||
                      quote.symbol.includes(".BO"))
                );

                const termStocks = stockQuotes.map((quote) => ({
                  symbol: quote.symbol,
                  name: quote.longname || quote.shortname || quote.symbol,
                  exchange: quote.exchDisp || quote.exchange || "Unknown",
                  type: "Common Stock",
                  currency: "INR",
                  country: "India",
                  sector: quote.sector || "Unknown",
                  industry: quote.industry || "Unknown",
                }));

                // Avoid duplicates
                const existingSymbols = new Set(
                  allIndianStocks.map((s) => s.symbol)
                );
                const newStocks = termStocks.filter(
                  (s) => !existingSymbols.has(s.symbol)
                );
                allIndianStocks = [...allIndianStocks, ...newStocks];

                console.log(
                  `🔤 Search "${term}": +${newStocks.length} new stocks (Total: ${allIndianStocks.length})`
                );

                // Delay to avoid rate limiting
                await new Promise((resolve) => setTimeout(resolve, 50));
              }
            } catch (termError) {
              console.error(
                `❌ Error searching term "${term}":`,
                termError.message
              );
            }
          }
        }

        companies = allIndianStocks;
        console.log(`🎯 Total Indian stocks fetched: ${companies.length}`);
      } catch (indianStockError) {
        console.error(
          "❌ Error fetching Indian stocks:",
          indianStockError.message
        );
      }
    }

    // Strategy 3: If no search or India-specific fetch didn't work, use screener API for trending stocks
    if (companies.length === 0) {
      console.log(`📈 Fetching trending stocks for region ${region}`);

      try {
        const screenerUrl = `https://${RAPIDAPI_HOST}/api/screener/list-by-predefined-screener`;
        const screenerResponse = await axios.get(screenerUrl, {
          ...rapidApiConfig,
          params: {
            screener_name: "most_actives",
            region: region,
            count: parseInt(limit) || 100,
          },
        });

        if (
          screenerResponse.data &&
          screenerResponse.data.finance &&
          screenerResponse.data.finance.result &&
          screenerResponse.data.finance.result[0] &&
          screenerResponse.data.finance.result[0].quotes
        ) {
          const quotes = screenerResponse.data.finance.result[0].quotes;

          companies = quotes.map((quote) => ({
            symbol: quote.symbol,
            name: quote.longName || quote.shortName || quote.symbol,
            exchange: quote.fullExchangeName || quote.exchange || "Unknown",
            type: "Common Stock",
            currency: quote.currency || (tab === "INDIA" ? "INR" : "USD"),
            country: tab === "INDIA" ? "India" : "United States",
            currentPrice: quote.regularMarketPrice || 0,
            change: quote.regularMarketChange || 0,
            percentChange: quote.regularMarketChangePercent || 0,
            volume: quote.regularMarketVolume || 0,
            marketCap: quote.marketCap || 0,
          }));

          console.log(`📊 Screener found ${companies.length} trending stocks`);
        }
      } catch (screenerError) {
        console.error("❌ Screener API error:", screenerError.message);
      }
    }

    // Strategy 3: If APIs fail, use fallback lists
    if (companies.length === 0) {
      console.log("📊 APIs failed, using fallback stock lists");

      if (tab === "INDIA") {
        companies = INDIAN_STOCKS.filter((stock) => {
          if (exchange === "NSE") return stock.symbol.includes(".NS");
          if (exchange === "BSE") return stock.symbol.includes(".BO");
          return true;
        });
      } else {
        companies = GLOBAL_STOCKS;
      }
    }

    // Apply exchange filtering for India
    if (
      tab === "INDIA" &&
      exchange &&
      exchange !== "ALL" &&
      companies.length > 0
    ) {
      if (exchange === "NSE") {
        companies = companies.filter(
          (stock) =>
            stock.symbol.includes(".NS") ||
            stock.exchange?.toLowerCase().includes("nse") ||
            stock.exchange?.toLowerCase().includes("national")
        );
      } else if (exchange === "BSE") {
        companies = companies.filter(
          (stock) =>
            stock.symbol.includes(".BO") ||
            stock.exchange?.toLowerCase().includes("bse") ||
            stock.exchange?.toLowerCase().includes("bombay")
        );
      }
    }

    // Apply pagination after filtering
    const pageNumber = parseInt(page) || 1;
    const pageSize = parseInt(limit) || 50;
    const startIndex = (pageNumber - 1) * pageSize;
    const endIndex = startIndex + pageSize;

    const totalCompanies = companies.length;
    const paginatedCompanies = companies.slice(startIndex, endIndex);
    const hasMore = endIndex < totalCompanies;

    console.log(
      `✅ Final result: Page ${pageNumber}, ${paginatedCompanies.length}/${totalCompanies} companies for tab ${tab} (${exchange}), hasMore: ${hasMore}`
    );

    res.json({
      companies: paginatedCompanies,
      totalCount: totalCompanies,
      currentPage: pageNumber,
      pageSize: pageSize,
      hasMore: hasMore,
      totalPages: Math.ceil(totalCompanies / pageSize),
      total: companies.length,
      tab,
      exchange: tab === "INDIA" ? exchange : "GLOBAL",
      region,
      source:
        companies.length > 0 && companies[0].currentPrice
          ? "Yahoo Finance Live Data"
          : "Fallback Database",
      searchApplied: search || null,
    });
  } catch (error) {
    console.error("❌ Error in stock-companies endpoint:", error);
    res.status(500).json({
      error: "Failed to fetch stock companies",
      message: error.message,
    });
  }
});

/**
 * Delete an MF investment
 */
app.delete("/mf-investment/:id", verifyToken, async (req, res) => {
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

// --- Stock Companies API Endpoints ---

/**
 * Get stock quote for a specific symbol using Yahoo Finance RapidAPI
 */
app.get("/api/stock-quote/:symbol", async (req, res) => {
  try {
    const { symbol } = req.params;
    console.log(`Fetching quote for symbol: ${symbol}`);

    const url = `https://${RAPIDAPI_HOST}/api/stock/get-detail`;

    const response = await axios.get(url, {
      ...rapidApiConfig,
      params: {
        symbol: symbol,
        region: symbol.includes(".NS") || symbol.includes(".BO") ? "IN" : "US",
      },
    });

    const data = response.data;

    if (!data || !data.price) {
      return res.status(404).json({
        error: "Stock not found",
        symbol: symbol,
      });
    }

    // Extract relevant information
    const currentPrice = data.price.regularMarketPrice?.raw || 0;
    const previousClose = data.price.regularMarketPreviousClose?.raw || 0;
    const change = currentPrice - previousClose;
    const percentChange = previousClose ? (change / previousClose) * 100 : 0;

    res.json({
      symbol,
      companyName: data.price.longName || data.price.shortName || symbol,
      currentPrice,
      previousClose,
      change,
      percentChange: parseFloat(percentChange.toFixed(2)),
      dayHigh: data.price.regularMarketDayHigh?.raw || 0,
      dayLow: data.price.regularMarketDayLow?.raw || 0,
      openPrice: data.price.regularMarketOpen?.raw || 0,
      volume: data.price.regularMarketVolume?.raw || 0,
      marketCap: data.summaryDetail?.marketCap?.raw || 0,
      currency:
        data.price.currency ||
        (symbol.includes(".NS") || symbol.includes(".BO") ? "INR" : "USD"),
      exchange:
        data.price.exchangeName || data.price.fullExchangeName || "Unknown",
      lastUpdated: new Date().toISOString(),
    });
  } catch (error) {
    console.error(
      `Error fetching stock quote for ${req.params.symbol}:`,
      error.message
    );
    res.status(500).json({
      error: "Failed to fetch stock quote",
      message: error.message,
    });
  }
});

/**
 * Get multiple stock quotes at once using Yahoo Finance RapidAPI
 */
app.post("/api/stock-quotes", async (req, res) => {
  try {
    const { symbols } = req.body;

    if (!symbols || !Array.isArray(symbols)) {
      return res.status(400).json({ error: "Symbols array is required" });
    }

    console.log(`Fetching quotes for ${symbols.length} symbols:`, symbols);

    const promises = symbols.map(async (symbol) => {
      try {
        const url = `https://${RAPIDAPI_HOST}/api/stock/get-detail`;

        const response = await axios.get(url, {
          ...rapidApiConfig,
          params: {
            symbol: symbol,
            region:
              symbol.includes(".NS") || symbol.includes(".BO") ? "IN" : "US",
          },
        });

        const data = response.data;

        if (!data || !data.price) {
          return {
            symbol,
            error: "Stock not found",
            currentPrice: 0,
            percentChange: 0,
          };
        }

        // Extract relevant information
        const currentPrice = data.price.regularMarketPrice?.raw || 0;
        const previousClose = data.price.regularMarketPreviousClose?.raw || 0;
        const change = currentPrice - previousClose;
        const percentChange = previousClose
          ? (change / previousClose) * 100
          : 0;

        return {
          symbol,
          companyName: data.price.longName || data.price.shortName || symbol,
          currentPrice,
          previousClose,
          change,
          percentChange: parseFloat(percentChange.toFixed(2)),
          dayHigh: data.price.regularMarketDayHigh?.raw || 0,
          dayLow: data.price.regularMarketDayLow?.raw || 0,
          openPrice: data.price.regularMarketOpen?.raw || 0,
          volume: data.price.regularMarketVolume?.raw || 0,
          marketCap: data.summaryDetail?.marketCap?.raw || 0,
          currency:
            data.price.currency ||
            (symbol.includes(".NS") || symbol.includes(".BO") ? "INR" : "USD"),
          exchange:
            data.price.exchangeName || data.price.fullExchangeName || "Unknown",
          error: null,
        };
      } catch (error) {
        console.error(`Error fetching quote for ${symbol}:`, error.message);
        return {
          symbol,
          error: error.message,
          currentPrice: 0,
          percentChange: 0,
        };
      }
    });

    const results = await Promise.all(promises);
    console.log(
      `Successfully fetched ${results.filter((r) => !r.error).length} out of ${
        symbols.length
      } quotes`
    );

    res.json({ data: results });
  } catch (error) {
    console.error("Error fetching multiple stock quotes:", error);
    res.status(500).json({
      error: "Failed to fetch stock quotes",
      message: error.message,
    });
  }
});

// --- Stock Transaction API Endpoints ---

/**
 * Add a new stock transaction (buy/sell)
 */
app.post("/api/stock-transactions", async (req, res) => {
  try {
    const {
      userName,
      symbol,
      companyName,
      type,
      quantity,
      price,
      total,
      date,
    } = req.body;

    // Validate required fields
    if (
      !userName ||
      !symbol ||
      !companyName ||
      !type ||
      !quantity ||
      !price ||
      !total ||
      !date
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Validate transaction type
    if (!["buy", "sell"].includes(type)) {
      return res
        .status(400)
        .json({ error: "Transaction type must be 'buy' or 'sell'" });
    }

    const stockTransaction = new StockTransaction({
      userName,
      symbol,
      companyName,
      type,
      quantity: Number(quantity),
      price: Number(price),
      total: Number(total),
      date,
    });

    await stockTransaction.save();

    res.status(201).json({
      message: "Stock transaction added successfully",
      transaction: stockTransaction,
    });
  } catch (error) {
    console.error("Error adding stock transaction:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get all stock transactions for a user
 */
app.get("/api/stock-transactions/:userName", async (req, res) => {
  try {
    const { userName } = req.params;
    const { symbol, type, limit = 50, page = 1 } = req.query;

    const filter = { userName };
    if (symbol) filter.symbol = symbol;
    if (type) filter.type = type;

    const skip = (page - 1) * limit;

    const transactions = await StockTransaction.find(filter)
      .sort({ timestamp: -1 })
      .limit(Number(limit))
      .skip(skip);

    const total = await StockTransaction.countDocuments(filter);

    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: Number(page),
      totalTransactions: total,
    });
  } catch (error) {
    console.error("Error fetching stock transactions:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get user's stock portfolio (aggregated holdings)
 */
app.get("/api/stock-portfolio/:userName", async (req, res) => {
  try {
    const { userName } = req.params;

    const portfolio = await StockTransaction.aggregate([
      { $match: { userName } },
      {
        $group: {
          _id: "$symbol",
          companyName: { $first: "$companyName" },
          totalShares: {
            $sum: {
              $cond: [
                { $eq: ["$type", "buy"] },
                "$quantity",
                { $multiply: ["$quantity", -1] },
              ],
            },
          },
          totalInvested: {
            $sum: {
              $cond: [
                { $eq: ["$type", "buy"] },
                "$total",
                { $multiply: ["$total", -1] },
              ],
            },
          },
          averagePrice: {
            $avg: {
              $cond: [{ $eq: ["$type", "buy"] }, "$price", null],
            },
          },
          lastTransaction: { $max: "$timestamp" },
        },
      },
      { $match: { totalShares: { $gt: 0 } } }, // Only show stocks with positive holdings
      { $sort: { lastTransaction: -1 } },
    ]);

    res.json({ portfolio });
  } catch (error) {
    console.error("Error fetching stock portfolio:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Delete a stock transaction
 */
app.delete("/api/stock-transactions/:transactionId", async (req, res) => {
  try {
    const { transactionId } = req.params;

    const deletedTransaction = await StockTransaction.findByIdAndDelete(
      transactionId
    );

    if (!deletedTransaction) {
      return res.status(404).json({ error: "Stock transaction not found" });
    }

    res.json({
      message: "Stock transaction deleted successfully",
      transaction: deletedTransaction,
    });
  } catch (error) {
    console.error("Error deleting stock transaction:", error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Get trending stocks for a specific region
 */
app.get("/api/trending-stocks", async (req, res) => {
  try {
    const { region = "US" } = req.query;

    const url = `https://${RAPIDAPI_HOST}/api/screener/list-by-predefined-screener`;

    const response = await axios.get(url, {
      ...rapidApiConfig,
      params: {
        screener_name: "most_actives",
        region: region,
        count: 25,
      },
    });

    const data = response.data;

    if (
      !data ||
      !data.finance ||
      !data.finance.result ||
      !data.finance.result[0]
    ) {
      return res.json([]);
    }

    const quotes = data.finance.result[0].quotes || [];

    const trendingStocks = quotes.map((quote) => ({
      symbol: quote.symbol,
      name: quote.longName || quote.shortName || quote.symbol,
      currentPrice: quote.regularMarketPrice || 0,
      change: quote.regularMarketChange || 0,
      percentChange: quote.regularMarketChangePercent || 0,
      volume: quote.regularMarketVolume || 0,
      exchange: quote.fullExchangeName || quote.exchange || "Unknown",
      currency: quote.currency || (region === "IN" ? "INR" : "USD"),
      country: region === "IN" ? "India" : "United States",
    }));

    res.json(trendingStocks);
  } catch (error) {
    console.error("Error fetching trending stocks:", error);
    res.status(500).json({
      error: "Failed to fetch trending stocks",
      message: error.message,
    });
  }
});

/**
 * Search for stocks globally using Yahoo Finance RapidAPI
 */
app.get("/api/search-stocks", async (req, res) => {
  try {
    const { q: query, region = "US", limit = 50 } = req.query;

    if (!query || query.trim().length < 1) {
      return res.status(400).json({ error: "Search query is required" });
    }

    console.log(
      `🔍 Searching stocks globally for: "${query}" in region: ${region}`
    );

    const url = `https://${RAPIDAPI_HOST}/api/autocomplete`;

    const response = await axios.get(url, {
      ...rapidApiConfig,
      params: {
        q: query.trim(),
        region: region,
      },
    });

    const data = response.data;

    if (!data || !data.quotes) {
      return res.json([]);
    }

    // Filter for stocks only
    const stockQuotes = data.quotes.filter(
      (quote) =>
        quote.typeDisp === "Equity" ||
        quote.quoteType === "EQUITY" ||
        quote.isYahooFinance === true
    );

    const searchResults = stockQuotes
      .slice(0, parseInt(limit))
      .map((quote) => ({
        symbol: quote.symbol,
        name: quote.longname || quote.shortname || quote.symbol,
        exchange: quote.exchDisp || quote.exchange || "Unknown",
        type: "Common Stock",
        currency: region === "IN" ? "INR" : "USD",
        country:
          region === "IN"
            ? "India"
            : region === "US"
            ? "United States"
            : "Global",
        sector: quote.sector || "Unknown",
        industry: quote.industry || "Unknown",
      }));

    console.log(`📊 Found ${searchResults.length} stocks matching "${query}"`);
    res.json({
      results: searchResults,
      total: searchResults.length,
      query: query,
      region: region,
    });
  } catch (error) {
    console.error("❌ Error searching stocks:", error);
    res.status(500).json({
      error: "Failed to search stocks",
      message: error.message,
    });
  }
});

/**
 * Get stocks by market/exchange - COMPREHENSIVE EXCHANGE DATA
 */
app.get("/api/stocks-by-exchange", async (req, res) => {
  try {
    const { exchange = "NASDAQ", region = "US", limit = 100 } = req.query;

    console.log(
      `🔍 Fetching stocks from exchange: ${exchange} in region: ${region}`
    );

    // Map exchange names to screener names for better results
    const screenerMap = {
      NASDAQ: "most_actives",
      NYSE: "most_actives",
      NSE: "most_actives",
      BSE: "most_actives",
      LSE: "most_actives", // London Stock Exchange
      TSE: "most_actives", // Tokyo Stock Exchange
      HKEX: "most_actives", // Hong Kong Exchange
    };

    const screenerName = screenerMap[exchange.toUpperCase()] || "most_actives";

    const url = `https://${RAPIDAPI_HOST}/api/screener/list-by-predefined-screener`;

    const response = await axios.get(url, {
      ...rapidApiConfig,
      params: {
        screener_name: screenerName,
        region: region,
        count: parseInt(limit),
      },
    });

    const data = response.data;

    if (
      !data ||
      !data.finance ||
      !data.finance.result ||
      !data.finance.result[0]
    ) {
      return res.json([]);
    }

    const quotes = data.finance.result[0].quotes || [];

    // Filter by exchange if specified
    let filteredQuotes = quotes;
    if (exchange && exchange !== "ALL") {
      filteredQuotes = quotes.filter(
        (quote) =>
          quote.exchange === exchange.toUpperCase() ||
          quote.fullExchangeName
            ?.toLowerCase()
            .includes(exchange.toLowerCase()) ||
          quote.symbol.includes(getExchangeSuffix(exchange))
      );
    }

    const stocks = filteredQuotes.map((quote) => ({
      symbol: quote.symbol,
      name: quote.longName || quote.shortName || quote.symbol,
      currentPrice: quote.regularMarketPrice || 0,
      change: quote.regularMarketChange || 0,
      percentChange: quote.regularMarketChangePercent || 0,
      volume: quote.regularMarketVolume || 0,
      exchange: quote.fullExchangeName || quote.exchange || exchange,
      currency: quote.currency || getCurrencyForRegion(region),
      country: getCountryForRegion(region),
      type: "Common Stock",
      marketCap: quote.marketCap || 0,
    }));

    console.log(`📊 Found ${stocks.length} stocks from ${exchange}`);
    res.json({
      stocks: stocks,
      total: stocks.length,
      exchange: exchange,
      region: region,
    });
  } catch (error) {
    console.error("❌ Error fetching stocks by exchange:", error);
    res.status(500).json({
      error: "Failed to fetch stocks by exchange",
      message: error.message,
    });
  }
});

// Helper functions for exchange mapping
function getExchangeSuffix(exchange) {
  const suffixMap = {
    NSE: ".NS",
    BSE: ".BO",
    LSE: ".L",
    TSE: ".T",
    HKEX: ".HK",
  };
  return suffixMap[exchange.toUpperCase()] || "";
}

function getCurrencyForRegion(region) {
  const currencyMap = {
    IN: "INR",
    US: "USD",
    GB: "GBP",
    JP: "JPY",
    HK: "HKD",
    CA: "CAD",
    AU: "AUD",
  };
  return currencyMap[region.toUpperCase()] || "USD";
}

function getCountryForRegion(region) {
  const countryMap = {
    IN: "India",
    US: "United States",
    GB: "United Kingdom",
    JP: "Japan",
    HK: "Hong Kong",
    CA: "Canada",
    AU: "Australia",
  };
  return countryMap[region.toUpperCase()] || "Unknown";
}

// � **MF (Mutual Fund) CRUD Operations**

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
app.post("/api/mf-investments", verifyToken, async (req, res) => {
  try {
    console.log("💰 Creating MF investment for user:", req.user.userName);
    console.log("💰 Received MF investment data:", req.body);

    const {
      name,
      amount,
      monthlyDeposit,
      duration,
      description,
      startDate,
      goalId,
    } = req.body;

    // Basic validation
    if (!name || !monthlyDeposit || !duration) {
      return res.status(400).json({
        error: "Name, monthly deposit amount, and duration are required.",
      });
    }

    const newMFInvestment = new Investment({
      name,
      amount: parseFloat(monthlyDeposit), // Initial amount is monthly deposit
      currentAmount: parseFloat(monthlyDeposit),
      interestRate: 12, // Default 12% for MF SIP
      investmentType: "Mutual Fund",
      startDate: startDate ? new Date(startDate) : new Date(),
      description: description || `SIP in ${name}`,
      monthlyDeposit: parseFloat(monthlyDeposit),
      duration: parseFloat(duration),
      goalId: goalId || null,
      userName: req.user.userName,
      compoundingFrequency: "monthly",
    });

    await newMFInvestment.save();

    console.log("✅ MF investment created successfully:", newMFInvestment._id);
    res.status(201).json(newMFInvestment);
  } catch (err) {
    console.error("❌ Error creating MF investment:", err);
    res
      .status(500)
      .json({ error: err.message || "Failed to add MF investment" });
  }
});

/**
 * Get a specific MF investment by ID
 */
app.get("/api/mf-investments/:id", verifyToken, async (req, res) => {
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
        .json({ error: "MF investment not found or not authorized" });
    }

    res.json(mfInvestment);
  } catch (err) {
    console.error("❌ Error fetching MF investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Update an MF investment
 */
app.put("/api/mf-investments/:id", verifyToken, async (req, res) => {
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
        .json({ error: "MF investment not found or not authorized" });
    }

    // Update allowed fields
    const updateData = {
      ...req.body,
      investmentType: "Mutual Fund", // Ensure it remains MF
      userName: userName, // Ensure ownership doesn't change
    };

    const updatedMFInvestment = await Investment.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );

    console.log(
      "✅ MF investment updated successfully:",
      updatedMFInvestment._id
    );
    res.json(updatedMFInvestment);
  } catch (err) {
    console.error("❌ Error updating MF investment:", err);
    res.status(500).json({ error: err.message });
  }
});

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
        .json({ error: "MF investment not found or not authorized" });
    }

    await Investment.findByIdAndDelete(req.params.id);

    console.log("✅ MF investment deleted successfully:", req.params.id);
    res.json({ message: "MF investment deleted successfully" });
  } catch (err) {
    console.error("❌ Error deleting MF investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get MF portfolio summary for a user
 */
app.get("/api/mf-portfolio", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const mfInvestments = await Investment.find({
      userName: userName,
      investmentType: "Mutual Fund",
    }).sort({ startDate: -1 });

    // Calculate portfolio summary
    const totalInvestments = mfInvestments.length;
    const totalInvested = mfInvestments.reduce(
      (sum, inv) => sum + inv.amount,
      0
    );
    const totalCurrentValue = mfInvestments.reduce(
      (sum, inv) => sum + inv.currentAmount,
      0
    );
    const totalMonthlyDeposit = mfInvestments.reduce(
      (sum, inv) => sum + (inv.monthlyDeposit || 0),
      0
    );
    const totalProfit = totalCurrentValue - totalInvested;
    const profitPercentage =
      totalInvested > 0 ? ((totalProfit / totalInvested) * 100).toFixed(2) : 0;

    // Group by goal if goalId exists
    const groupedByGoal = mfInvestments.reduce((acc, investment) => {
      const goalId = investment.goalId || "no-goal";
      if (!acc[goalId]) {
        acc[goalId] = {
          goalId: goalId,
          investments: [],
          totalInvested: 0,
          totalCurrentValue: 0,
          totalMonthlyDeposit: 0,
        };
      }
      acc[goalId].investments.push(investment);
      acc[goalId].totalInvested += investment.amount;
      acc[goalId].totalCurrentValue += investment.currentAmount;
      acc[goalId].totalMonthlyDeposit += investment.monthlyDeposit || 0;
      return acc;
    }, {});

    res.json({
      summary: {
        totalInvestments,
        totalInvested,
        totalCurrentValue,
        totalMonthlyDeposit,
        totalProfit,
        profitPercentage: parseFloat(profitPercentage),
      },
      investments: mfInvestments,
      groupedByGoal: Object.values(groupedByGoal),
    });
  } catch (err) {
    console.error("❌ Error fetching MF portfolio:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get MF investment performance analytics
 */
app.get("/api/mf-analytics", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const mfInvestments = await Investment.find({
      userName: userName,
      investmentType: "Mutual Fund",
    }).sort({ startDate: 1 });

    if (mfInvestments.length === 0) {
      return res.json({
        message: "No MF investments found",
        analytics: {
          monthlyGrowth: [],
          performanceMetrics: {
            bestPerformer: null,
            worstPerformer: null,
            averageReturn: 0,
            totalSIPAmount: 0,
          },
        },
      });
    }

    // Calculate individual investment performance
    const investmentPerformance = mfInvestments.map((investment) => {
      const invested = investment.amount;
      const current = investment.currentAmount;
      const profit = current - invested;
      const profitPercentage = invested > 0 ? (profit / invested) * 100 : 0;

      return {
        id: investment._id,
        name: investment.name,
        invested,
        current,
        profit,
        profitPercentage: parseFloat(profitPercentage.toFixed(2)),
        monthlyDeposit: investment.monthlyDeposit || 0,
        duration: investment.duration || 0,
      };
    });

    // Find best and worst performers
    const bestPerformer = investmentPerformance.reduce((best, current) =>
      current.profitPercentage > best.profitPercentage ? current : best
    );

    const worstPerformer = investmentPerformance.reduce((worst, current) =>
      current.profitPercentage < worst.profitPercentage ? current : worst
    );

    // Calculate average return
    const averageReturn =
      investmentPerformance.length > 0
        ? investmentPerformance.reduce(
            (sum, inv) => sum + inv.profitPercentage,
            0
          ) / investmentPerformance.length
        : 0;

    // Calculate total SIP amount
    const totalSIPAmount = mfInvestments.reduce(
      (sum, inv) => sum + (inv.monthlyDeposit || 0),
      0
    );

    // Generate monthly growth data (simulated based on investment dates)
    const monthlyGrowth = [];
    const currentDate = new Date();
    const startDate = new Date(
      Math.min(...mfInvestments.map((inv) => new Date(inv.startDate).getTime()))
    );

    for (
      let d = new Date(startDate);
      d <= currentDate;
      d.setMonth(d.getMonth() + 1)
    ) {
      const monthKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(
        2,
        "0"
      )}`;

      // Calculate cumulative investment and value for this month
      const relevantInvestments = mfInvestments.filter(
        (inv) => new Date(inv.startDate) <= d
      );

      const monthlyInvested = relevantInvestments.reduce(
        (sum, inv) => sum + inv.amount,
        0
      );
      const monthlyValue = relevantInvestments.reduce(
        (sum, inv) => sum + inv.currentAmount,
        0
      );

      monthlyGrowth.push({
        month: monthKey,
        invested: monthlyInvested,
        value: monthlyValue,
        profit: monthlyValue - monthlyInvested,
      });
    }

    res.json({
      analytics: {
        investmentPerformance,
        monthlyGrowth,
        performanceMetrics: {
          bestPerformer,
          worstPerformer,
          averageReturn: parseFloat(averageReturn.toFixed(2)),
          totalSIPAmount,
        },
        summary: {
          totalInvestments: mfInvestments.length,
          totalInvested: mfInvestments.reduce(
            (sum, inv) => sum + inv.amount,
            0
          ),
          totalCurrentValue: mfInvestments.reduce(
            (sum, inv) => sum + inv.currentAmount,
            0
          ),
        },
      },
    });
  } catch (err) {
    console.error("❌ Error fetching MF analytics:", err);
    res.status(500).json({ error: err.message });
  }
});

// �🔹 **Start Server**
// 📈 **Stock (Equity) CRUD Operations**

/**
 * Get all stock investments for a user
 */
app.get("/api/stock-investments", verifyToken, async (req, res) => {
  try {
    console.log("📈 Getting stock investments for user:", req.user.userName);

    const userName = req.user.userName;
    const stockInvestments = await Investment.find({
      userName: userName,
      investmentType: "Stock",
    }).sort({ startDate: -1 });

    console.log("📈 Found stock investments:", stockInvestments.length);
    res.json(stockInvestments);
  } catch (err) {
    console.error("❌ Error fetching stock investments:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Create a new stock investment
 */
app.post("/api/stock-investments", verifyToken, async (req, res) => {
  try {
    console.log("💰 Creating stock investment for user:", req.user.userName);
    console.log("💰 Received stock investment data:", req.body);

    const {
      name,
      amount,
      stockSymbol,
      stockQuantity,
      stockPrice,
      description,
      startDate,
      goalId,
    } = req.body;

    // Basic validation
    if (!name || !amount || !stockSymbol || !stockQuantity || !stockPrice) {
      return res.status(400).json({
        error: "Name, amount, stock symbol, quantity, and price are required.",
      });
    }

    const newStockInvestment = new Investment({
      name,
      amount: parseFloat(amount),
      currentAmount: parseFloat(amount),
      interestRate: 0, // Stocks don't have fixed interest rate
      investmentType: "Stock",
      startDate: startDate ? new Date(startDate) : new Date(),
      description:
        description ||
        `${stockQuantity} shares of ${stockSymbol} at $${stockPrice} per share`,
      stockSymbol: stockSymbol.toUpperCase(),
      stockQuantity: parseFloat(stockQuantity),
      stockPrice: parseFloat(stockPrice),
      goalId: goalId || null,
      userName: req.user.userName,
    });

    await newStockInvestment.save();

    console.log(
      "✅ Stock investment created successfully:",
      newStockInvestment._id
    );
    res.status(201).json(newStockInvestment);
  } catch (err) {
    console.error("❌ Error creating stock investment:", err);
    res
      .status(500)
      .json({ error: err.message || "Failed to add stock investment" });
  }
});

/**
 * Get a specific stock investment by ID
 */
app.get("/api/stock-investments/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const stockInvestment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
      investmentType: "Stock",
    });

    if (!stockInvestment) {
      return res
        .status(404)
        .json({ error: "Stock investment not found or not authorized" });
    }

    res.json(stockInvestment);
  } catch (err) {
    console.error("❌ Error fetching stock investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Update a stock investment
 */
app.put("/api/stock-investments/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const stockInvestment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
      investmentType: "Stock",
    });

    if (!stockInvestment) {
      return res
        .status(404)
        .json({ error: "Stock investment not found or not authorized" });
    }

    // Update allowed fields
    const updateData = {
      ...req.body,
      investmentType: "Stock", // Ensure it remains a stock investment
      userName: userName, // Ensure ownership doesn't change
    };

    const updatedStockInvestment = await Investment.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );

    console.log(
      "✅ Stock investment updated successfully:",
      updatedStockInvestment._id
    );
    res.json(updatedStockInvestment);
  } catch (err) {
    console.error("❌ Error updating stock investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Delete a stock investment
 */
app.delete("/api/stock-investments/:id", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const stockInvestment = await Investment.findOne({
      _id: req.params.id,
      userName: userName,
      investmentType: "Stock",
    });

    if (!stockInvestment) {
      return res
        .status(404)
        .json({ error: "Stock investment not found or not authorized" });
    }

    await Investment.findByIdAndDelete(req.params.id);

    console.log("✅ Stock investment deleted successfully:", req.params.id);
    res.json({ message: "Stock investment deleted successfully" });
  } catch (err) {
    console.error("❌ Error deleting stock investment:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get stock portfolio summary for a user
 */
app.get("/api/stock-portfolio", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const stockInvestments = await Investment.find({
      userName: userName,
      investmentType: "Stock",
    }).sort({ startDate: -1 });

    // Group by stock symbol to create portfolio summary
    const portfolioMap = {};
    let totalInvestments = 0;
    let totalInvested = 0;
    let totalCurrentValue = 0;

    stockInvestments.forEach((investment) => {
      const symbol = investment.stockSymbol;
      if (!portfolioMap[symbol]) {
        portfolioMap[symbol] = {
          symbol,
          companyName: investment.name.split(" - ")[0] || symbol,
          totalShares: 0,
          totalInvested: 0,
          averagePrice: 0,
          transactions: [],
        };
      }

      portfolioMap[symbol].totalShares += investment.stockQuantity;
      portfolioMap[symbol].totalInvested += investment.amount;
      portfolioMap[symbol].transactions.push({
        type: investment.stockQuantity > 0 ? "buy" : "sell",
        quantity: Math.abs(investment.stockQuantity),
        price: investment.stockPrice,
        amount: investment.amount,
        date: investment.startDate,
        description: investment.description,
      });

      totalInvestments++;
      totalInvested += investment.amount;
      totalCurrentValue += investment.currentAmount;
    });

    // Calculate average prices and filter out zero holdings
    const portfolio = Object.values(portfolioMap)
      .map((item) => ({
        ...item,
        averagePrice:
          item.totalShares > 0 ? item.totalInvested / item.totalShares : 0,
      }))
      .filter((item) => item.totalShares > 0);

    const totalProfit = totalCurrentValue - totalInvested;
    const profitPercentage =
      totalInvested > 0 ? ((totalProfit / totalInvested) * 100).toFixed(2) : 0;

    res.json({
      summary: {
        totalInvestments,
        totalStocks: portfolio.length,
        totalInvested,
        totalCurrentValue,
        totalProfit,
        profitPercentage: parseFloat(profitPercentage),
      },
      portfolio,
      investments: stockInvestments,
    });
  } catch (err) {
    console.error("❌ Error fetching stock portfolio:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get stock investment performance analytics
 */
app.get("/api/stock-analytics", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;
    const stockInvestments = await Investment.find({
      userName: userName,
      investmentType: "Stock",
    }).sort({ startDate: 1 });

    if (stockInvestments.length === 0) {
      return res.json({
        message: "No stock investments found",
        analytics: {
          performanceMetrics: {
            bestPerformer: null,
            worstPerformer: null,
            totalReturn: 0,
            averageReturn: 0,
          },
          sectorAllocation: [],
          monthlyPerformance: [],
        },
      });
    }

    // Calculate individual stock performance
    const stockPerformance = {};
    stockInvestments.forEach((investment) => {
      const symbol = investment.stockSymbol;
      if (!stockPerformance[symbol]) {
        stockPerformance[symbol] = {
          symbol,
          name: investment.name.split(" - ")[0] || symbol,
          totalInvested: 0,
          totalCurrentValue: 0,
          totalShares: 0,
        };
      }

      stockPerformance[symbol].totalInvested += investment.amount;
      stockPerformance[symbol].totalCurrentValue += investment.currentAmount;
      stockPerformance[symbol].totalShares += investment.stockQuantity;
    });

    // Calculate performance metrics for each stock
    const performanceArray = Object.values(stockPerformance).map((stock) => {
      const profit = stock.totalCurrentValue - stock.totalInvested;
      const profitPercentage =
        stock.totalInvested > 0 ? (profit / stock.totalInvested) * 100 : 0;

      return {
        ...stock,
        profit,
        profitPercentage: parseFloat(profitPercentage.toFixed(2)),
        averagePrice:
          stock.totalShares > 0 ? stock.totalInvested / stock.totalShares : 0,
      };
    });

    // Find best and worst performers
    const bestPerformer =
      performanceArray.length > 0
        ? performanceArray.reduce((best, current) =>
            current.profitPercentage > best.profitPercentage ? current : best
          )
        : null;

    const worstPerformer =
      performanceArray.length > 0
        ? performanceArray.reduce((worst, current) =>
            current.profitPercentage < worst.profitPercentage ? current : worst
          )
        : null;

    // Calculate total return
    const totalInvested = performanceArray.reduce(
      (sum, stock) => sum + stock.totalInvested,
      0
    );
    const totalCurrentValue = performanceArray.reduce(
      (sum, stock) => sum + stock.totalCurrentValue,
      0
    );
    const totalReturn =
      totalInvested > 0
        ? ((totalCurrentValue - totalInvested) / totalInvested) * 100
        : 0;

    // Calculate average return
    const averageReturn =
      performanceArray.length > 0
        ? performanceArray.reduce(
            (sum, stock) => sum + stock.profitPercentage,
            0
          ) / performanceArray.length
        : 0;

    // Generate monthly performance data (simplified)
    const monthlyPerformance = [];
    const currentDate = new Date();
    const startDate =
      stockInvestments.length > 0
        ? new Date(
            Math.min(
              ...stockInvestments.map((inv) =>
                new Date(inv.startDate).getTime()
              )
            )
          )
        : new Date();

    for (
      let d = new Date(startDate);
      d <= currentDate;
      d.setMonth(d.getMonth() + 1)
    ) {
      const monthKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(
        2,
        "0"
      )}`;

      // Calculate cumulative investment and value for this month
      const relevantInvestments = stockInvestments.filter(
        (inv) => new Date(inv.startDate) <= d
      );

      const monthlyInvested = relevantInvestments.reduce(
        (sum, inv) => sum + inv.amount,
        0
      );
      const monthlyValue = relevantInvestments.reduce(
        (sum, inv) => sum + inv.currentAmount,
        0
      );

      monthlyPerformance.push({
        month: monthKey,
        invested: monthlyInvested,
        value: monthlyValue,
        profit: monthlyValue - monthlyInvested,
        return:
          monthlyInvested > 0
            ? ((monthlyValue - monthlyInvested) / monthlyInvested) * 100
            : 0,
      });
    }

    res.json({
      analytics: {
        performanceMetrics: {
          bestPerformer,
          worstPerformer,
          totalReturn: parseFloat(totalReturn.toFixed(2)),
          averageReturn: parseFloat(averageReturn.toFixed(2)),
          totalStocks: performanceArray.length,
        },
        stockPerformance: performanceArray,
        monthlyPerformance,
        summary: {
          totalInvestments: stockInvestments.length,
          totalInvested,
          totalCurrentValue,
          totalProfit: totalCurrentValue - totalInvested,
        },
      },
    });
  } catch (err) {
    console.error("❌ Error fetching stock analytics:", err);
    res.status(500).json({ error: err.message });
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
