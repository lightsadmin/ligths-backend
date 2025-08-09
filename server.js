require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"); //n
const axios = require("axios");
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
      "https://www.amfiindia.com/spages/NAVAll.txt"
    );
    const lines = response.data.split("\n");
    const updates = [];

    for (const line of lines) {
      if (line.trim() === "" || line.includes("Scheme Code")) continue;
      const parts = line.split(";");
      if (parts.length >= 4) {
        const schemeCode = parts[0].trim();
        const schemeName = parts[2].trim();
        const nav = parseFloat(parts[3].trim());

        if (schemeCode && schemeName && !isNaN(nav) && nav > 0) {
          updates.push({
            updateOne: {
              filter: { schemeCode: schemeCode },
              update: {
                $set: { schemeCode, schemeName, nav, lastUpdated: new Date() },
              },
              upsert: true,
            },
          });
        }
      }
    }

    if (updates.length > 0) {
      await MutualFund.bulkWrite(updates);
      console.log(
        `✅ NAV data updated successfully. Processed ${updates.length} funds.`
      );
    } else {
      console.log("ℹ️ No new NAV data to update.");
    }
  } catch (error) {
    console.error("❌ Error fetching NAV data:", error.message);
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
    const pipeline = [
      {
        $addFields: {
          companyName: {
            $trim: {
              input: { $arrayElemAt: [{ $split: ["$schemeName", " - "] }, 0] },
            },
          },
        },
      },
      { $match: { companyName: { $regex: search, $options: "i" } } },
      {
        $group: {
          _id: "$companyName",
          schemes: {
            $push: {
              schemeCode: "$schemeCode",
              schemeName: "$schemeName",
              nav: "$nav",
              lastUpdated: "$lastUpdated",
            },
          },
          lastUpdated: { $max: "$lastUpdated" },
        },
      },
      {
        $project: {
          _id: 0,
          companyName: "$_id",
          schemes: "$schemes",
          lastUpdated: "$lastUpdated",
        },
      },
      { $sort: { companyName: 1 } },
    ];
    const companies = await MutualFund.aggregate(pipeline);
    res.json(companies);
  } catch (error) {
    console.error("Error fetching grouped mutual funds:", error.message);
    res.status(500).json({ error: "Internal Server Error" });
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
    await fetchAndStoreNAVData();
    res.json({ message: "NAV data updated successfully" });
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
      currentAmount: parseFloat(amount),
      interestRate: parseFloat(interestRate),
      investmentType,
      startDate: new Date(),
      maturityDate,
      description,
      goalId,
      compoundingFrequency,
      monthlyDeposit,
      duration,
      userName: req.user.userName,
    });

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

// --- Stock Companies API Endpoints ---

/**
 * Get stock quote for a specific symbol
 */
app.get("/api/stock-quote/:symbol", async (req, res) => {
  try {
    const { symbol } = req.params;
    const FINNHUB_API_KEY = "d28seapr01qle9gsj64gd28seapr01qle9gsj650";

    // Fetch quote and profile simultaneously
    const [quoteResponse, profileResponse] = await Promise.all([
      axios.get(`https://finnhub.io/api/v1/quote`, {
        params: { symbol, token: FINNHUB_API_KEY },
      }),
      axios.get(`https://finnhub.io/api/v1/stock/profile2`, {
        params: { symbol, token: FINNHUB_API_KEY },
      }),
    ]);

    const quote = quoteResponse.data;
    const profile = profileResponse.data;

    // Calculate percentage change
    const percentChange = quote.pc
      ? (((quote.c - quote.pc) / quote.pc) * 100).toFixed(2)
      : 0;

    res.json({
      symbol,
      quote,
      profile,
      percentChange,
      formatted: {
        currentPrice: new Intl.NumberFormat("en-US", {
          style: "currency",
          currency: "USD",
        }).format(quote.c || 0),
        change: `${percentChange >= 0 ? "+" : ""}${percentChange}%`,
      },
    });
  } catch (error) {
    console.error(
      `Error fetching stock quote for ${req.params.symbol}:`,
      error
    );
    res.status(500).json({
      error: "Failed to fetch stock quote",
      message: error.message,
    });
  }
});

/**
 * Get multiple stock quotes at once
 */
app.post("/api/stock-quotes", async (req, res) => {
  try {
    const { symbols } = req.body;

    if (!symbols || !Array.isArray(symbols)) {
      return res.status(400).json({ error: "Symbols array is required" });
    }

    const FINNHUB_API_KEY = "d28seapr01qle9gsj64gd28seapr01qle9gsj650";

    const promises = symbols.map(async (symbol) => {
      try {
        const [quoteResponse, profileResponse] = await Promise.all([
          axios.get(`https://finnhub.io/api/v1/quote`, {
            params: { symbol, token: FINNHUB_API_KEY },
          }),
          axios.get(`https://finnhub.io/api/v1/stock/profile2`, {
            params: { symbol, token: FINNHUB_API_KEY },
          }),
        ]);

        const quote = quoteResponse.data;
        const profile = profileResponse.data;
        const percentChange = quote.pc
          ? (((quote.c - quote.pc) / quote.pc) * 100).toFixed(2)
          : 0;

        return {
          symbol,
          quote,
          profile,
          percentChange,
          error: null,
        };
      } catch (error) {
        return {
          symbol,
          quote: null,
          profile: null,
          percentChange: 0,
          error: error.message,
        };
      }
    });

    const results = await Promise.all(promises);
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
 * Get user's stock investments (from investments collection)
 */
app.get("/api/stock-investments/:userName", verifyToken, async (req, res) => {
  try {
    const userName = req.user.userName;

    // Get all stock investments for the user
    const stockInvestments = await Investment.find({
      userName: userName,
      investmentType: "Stock",
    }).sort({ startDate: -1 });

    // Group by stock symbol to get portfolio summary
    const portfolioMap = {};

    stockInvestments.forEach((investment) => {
      const symbol = investment.stockSymbol;
      if (!portfolioMap[symbol]) {
        portfolioMap[symbol] = {
          symbol,
          companyName: investment.name.split(" - ")[0],
          totalShares: 0,
          totalInvested: 0,
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
    });

    // Convert to array and filter out zero holdings
    const portfolio = Object.values(portfolioMap).filter(
      (item) => item.totalShares > 0
    );

    res.json({
      stockInvestments,
      portfolio,
      totalStocks: portfolio.length,
      totalInvested: portfolio.reduce(
        (sum, item) => sum + item.totalInvested,
        0
      ),
    });
  } catch (error) {
    console.error("Error fetching stock investments:", error);
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
 * Get all stock companies from Finnhub API with exchange and country filtering
 * Supports: US, India (NSE, BSE), UK, Hong Kong, and more
 */
app.get("/api/stock-companies", async (req, res) => {
  try {
    const { search, exchange = "US", country } = req.query;

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

    // Fetch data from all specified exchanges
    const allCompanies = [];

    for (const exchangeCode of exchangesToFetch) {
      try {
        const response = await fetch(
          `https://finnhub.io/api/v1/stock/symbol?exchange=${exchangeCode}&token=${FINNHUB_API_KEY}`
        );

        if (!response.ok) {
          console.warn(
            `Failed to fetch from exchange ${exchangeCode}: ${response.status}`
          );
          continue;
        }

        const exchangeCompanies = await response.json();

        if (Array.isArray(exchangeCompanies)) {
          // Add exchange info to each company
          const companiesWithExchange = exchangeCompanies.map((company) => ({
            ...company,
            exchange: exchangeCode,
            country: getCountryFromExchange(exchangeCode),
          }));

          allCompanies.push(...companiesWithExchange);
        }
      } catch (error) {
        console.warn(
          `Error fetching from exchange ${exchangeCode}:`,
          error.message
        );
      }
    }

    // Filter out companies with invalid symbols or names
    let filteredCompanies = allCompanies.filter(
      (company) =>
        company.symbol &&
        company.description &&
        company.description.trim() !== ""
    );

    // For Indian exchanges, allow longer symbols and dots
    if (exchangesToFetch.some((ex) => ["NS", "BO"].includes(ex))) {
      // Indian stocks can have longer symbols and dots
      filteredCompanies = filteredCompanies.filter(
        (company) => company.symbol.length <= 20 // Longer limit for Indian stocks
      );
    } else {
      // For other exchanges, keep the original filtering
      filteredCompanies = filteredCompanies.filter(
        (company) => !company.symbol.includes(".") && company.symbol.length <= 8
      );
    }

    // If search query is provided, filter companies
    if (search && search.trim()) {
      const searchTerm = search.trim().toLowerCase();
      filteredCompanies = filteredCompanies.filter(
        (company) =>
          company.symbol.toLowerCase().includes(searchTerm) ||
          company.description.toLowerCase().includes(searchTerm)
      );
    }

    // Sort by symbol for consistency
    filteredCompanies.sort((a, b) => a.symbol.localeCompare(b.symbol));

    // Limit to reasonable number and format response
    const limitedCompanies = filteredCompanies
      .slice(0, 2000)
      .map((company) => ({
        symbol: company.symbol,
        name: company.description,
        displayName: company.displaySymbol || company.symbol,
        type: company.type || "Common Stock",
        exchange: company.exchange,
        country: company.country,
        currency: company.currency || getCurrencyFromExchange(company.exchange),
        mic: company.mic, // Market Identifier Code
      }));

    // Group by exchange for better organization
    const groupedByExchange = limitedCompanies.reduce((acc, company) => {
      const exchangeName = getExchangeName(company.exchange);
      if (!acc[exchangeName]) {
        acc[exchangeName] = [];
      }
      acc[exchangeName].push(company);
      return acc;
    }, {});

    res.json({
      companies: limitedCompanies,
      groupedByExchange,
      total: limitedCompanies.length,
      totalAvailable: filteredCompanies.length,
      exchanges: exchangesToFetch,
      search: search || "",
      requestedExchange: exchange,
      requestedCountry: country,
      message:
        limitedCompanies.length === 0
          ? `No companies found for exchange ${exchange}. This may be due to API key limitations or exchange availability.`
          : null,
    });
  } catch (error) {
    console.error("Error fetching stock companies:", error);
    res.status(500).json({
      error: "Failed to fetch stock companies",
      message: error.message,
    });
  }
});

// Helper function to get country from exchange code
function getCountryFromExchange(exchangeCode) {
  const countryMap = {
    NS: "India",
    BO: "India",
    US: "United States",
    L: "United Kingdom",
    HK: "Hong Kong",
    TO: "Canada",
    F: "Germany",
    T: "Japan",
    AX: "Australia",
  };
  return countryMap[exchangeCode] || "Unknown";
}

// Helper function to get currency from exchange
function getCurrencyFromExchange(exchangeCode) {
  const currencyMap = {
    NS: "INR",
    BO: "INR",
    US: "USD",
    L: "GBP",
    HK: "HKD",
    TO: "CAD",
    F: "EUR",
    T: "JPY",
    AX: "AUD",
  };
  return currencyMap[exchangeCode] || "USD";
}

// Helper function to get exchange display name
function getExchangeName(exchangeCode) {
  const nameMap = {
    NS: "NSE (National Stock Exchange of India)",
    BO: "BSE (Bombay Stock Exchange)",
    US: "US Exchanges (NASDAQ, NYSE)",
    L: "London Stock Exchange",
    HK: "Hong Kong Stock Exchange",
    TO: "Toronto Stock Exchange",
    F: "Frankfurt Stock Exchange",
    T: "Tokyo Stock Exchange",
    AX: "Australian Securities Exchange",
  };
  return nameMap[exchangeCode] || exchangeCode;
}

/**
 * Get available exchanges and their status
 */
app.get("/api/stock-exchanges", async (req, res) => {
  try {
    const FINNHUB_API_KEY = "d28seapr01qle9gsj64gd28seapr01qle9gsj650";

    const exchangesToTest = [
      {
        code: "US",
        name: "US Exchanges (NASDAQ, NYSE)",
        country: "United States",
      },
      {
        code: "NS",
        name: "National Stock Exchange of India",
        country: "India",
      },
      { code: "BO", name: "Bombay Stock Exchange", country: "India" },
      { code: "L", name: "London Stock Exchange", country: "United Kingdom" },
      { code: "HK", name: "Hong Kong Stock Exchange", country: "Hong Kong" },
      { code: "TO", name: "Toronto Stock Exchange", country: "Canada" },
      { code: "F", name: "Frankfurt Stock Exchange", country: "Germany" },
      { code: "T", name: "Tokyo Stock Exchange", country: "Japan" },
      {
        code: "AX",
        name: "Australian Securities Exchange",
        country: "Australia",
      },
    ];

    const exchangeStatus = [];

    for (const exchange of exchangesToTest) {
      try {
        const response = await fetch(
          `https://finnhub.io/api/v1/stock/symbol?exchange=${exchange.code}&token=${FINNHUB_API_KEY}`
        );

        if (response.ok) {
          const data = await response.json();
          exchangeStatus.push({
            ...exchange,
            available: true,
            totalCompanies: Array.isArray(data) ? data.length : 0,
            status: "Available",
          });
        } else {
          exchangeStatus.push({
            ...exchange,
            available: false,
            totalCompanies: 0,
            status: `HTTP ${response.status}`,
          });
        }
      } catch (error) {
        exchangeStatus.push({
          ...exchange,
          available: false,
          totalCompanies: 0,
          status: `Error: ${error.message}`,
        });
      }
    }

    res.json({
      exchanges: exchangeStatus,
      availableExchanges: exchangeStatus.filter(
        (ex) => ex.available && ex.totalCompanies > 0
      ),
      totalExchangesTested: exchangesToTest.length,
    });
  } catch (error) {
    console.error("Error checking exchange availability:", error);
    res.status(500).json({
      error: "Failed to check exchange availability",
      message: error.message,
    });
  }
});

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
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(
    `📱 Mobile devices can connect at: http://192.168.30.236:${PORT}`
  );
  console.log(`💻 Local access: http://localhost:${PORT}`);
});
