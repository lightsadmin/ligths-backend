require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const ObjectId = mongoose.Types.ObjectId;

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";
const RESET_TOKEN_SECRET =
  process.env.RESET_TOKEN_SECRET || "resettoken_secret_key";
const EMAIL_USER = process.env.EMAIL_USER; // Your email
const EMAIL_PASS = process.env.EMAIL_PASS; // Your email password/app password
const FRONTEND_URL = process.env.FRONTEND_URL || "https://your-app.com"; // Your app URL
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

// 📌 **Health Check Endpoint**
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "Server is running",
    timestamp: new Date().toISOString(),
    endpoints: {
      login: "/api/login",
      forgotPassword: "/api/forgot-password",
      resetPassword: "/api/reset-password",
    },
  });
});

// � **MongoDB Connection**
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
  user: { type: mongoose.Schema.Types.ObjectId, required: true },
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
});

const Investment = mongoose.model("Investment", investmentSchema);

// 📌 Define Goal Schema
const goalSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  name: { type: String, required: true },
  customName: { type: String },
  description: { type: String, required: false },
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

const Goal = mongoose.model("Goal", goalSchema);

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
      id: user._id,
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

// 📧 **Email Configuration for Password Reset**
let transporter = null;

// Only create transporter if email credentials are provided
if (EMAIL_USER && EMAIL_PASS) {
  try {
    transporter = nodemailer.createTransport({
      service: "gmail", // You can use other services like outlook, yahoo, etc.
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS, // Use app-specific password for Gmail
      },
    });
    console.log("✅ Email transporter configured successfully");
  } catch (error) {
    console.error("❌ Error configuring email transporter:", error);
  }
} else {
  console.warn(
    "⚠️ Email credentials not provided. Password reset functionality will be disabled."
  );
}

// 📌 **Test Route for Password Reset**
app.post("/api/test-forgot", async (req, res) => {
  console.log("🧪 Test forgot password route hit");
  res.json({ message: "Test route working", body: req.body });
});

// 📌 **Forgot Password Route**
app.post("/api/forgot-password", async (req, res) => {
  console.log("🔐 Forgot password route accessed");
  console.log("🔐 Request body:", req.body);

  const { email } = req.body;

  try {
    console.log("🔐 Processing forgot password for email:", email);

    if (!email) {
      console.log("❌ No email provided");
      return res.status(400).json({ error: "Email is required." });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log("❌ Invalid email format:", email);
      return res
        .status(400)
        .json({ error: "Please provide a valid email address." });
    }

    // Check if email service is configured
    if (!transporter) {
      console.error("❌ Email service not configured");
      return res.status(200).json({
        message:
          "Password reset functionality is currently unavailable. Please contact support.",
      });
    }

    // Search for user across all user collections
    let userFound = null;
    let userName = null;

    try {
      // Get all collections in the database
      const collections = await mongoose.connection.db
        .listCollections()
        .toArray();
      console.log("🔍 Searching across collections for email:", email);

      for (const collection of collections) {
        if (collection.name.endsWith("_users")) {
          const collectionUserName = collection.name.replace("_users", "");
          try {
            const UserModel = createUserModel(collectionUserName);
            const user = await UserModel.findOne({ email: email });
            if (user) {
              userFound = user;
              userName = collectionUserName;
              console.log("✅ User found in collection:", collectionUserName);
              break;
            }
          } catch (collectionError) {
            console.error(
              `❌ Error searching in collection ${collectionUserName}:`,
              collectionError.message
            );
            continue;
          }
        }
      }
    } catch (dbError) {
      console.error("❌ Database search error:", dbError.message);
      return res.status(500).json({ error: "Database error occurred." });
    }

    // Always return success to prevent email enumeration attacks
    if (!userFound) {
      console.log("❗ User not found for email:", email);
      return res.status(200).json({
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }

    try {
      // Generate secure reset token
      const resetToken = jwt.sign(
        {
          id: userFound._id,
          email: userFound.email,
          userName: userName,
          purpose: "password_reset",
        },
        RESET_TOKEN_SECRET,
        { expiresIn: "15m" } // Token expires in 15 minutes
      );

      // Create reset link (for now, just return success - you can configure the frontend URL later)
      const resetLink = `${FRONTEND_URL}/reset-password?token=${resetToken}`;

      // Email template
      const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #3498db;">Password Reset Request</h2>
          <p>Hello ${userFound.firstName || "User"},</p>
          <p>You have requested to reset your password for your Lights Finance account.</p>
          <p>Click the button below to reset your password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" 
               style="background-color: #3498db; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p><strong>This link will expire in 15 minutes.</strong></p>
          <p>If you did not request this password reset, please ignore this email.</p>
          <hr style="margin: 30px 0;">
          <p style="color: #7f8c8d; font-size: 12px;">
            Reset Link: ${resetLink}
          </p>
        </div>
      `;

      // Send email
      await transporter.sendMail({
        from: `"Lights Finance" <${EMAIL_USER}>`,
        to: email,
        subject: "Password Reset Request - Lights Finance",
        html: emailHtml,
      });

      console.log("✅ Password reset email sent to:", email);
    } catch (emailError) {
      console.error("❌ Error sending email:", emailError.message);
      // Still return success to prevent email enumeration
    }

    res.status(200).json({
      message:
        "If an account with that email exists, a password reset link has been sent.",
    });
  } catch (error) {
    console.error("❌ Unexpected error in forgot password:", error);
    res
      .status(500)
      .json({ error: "An unexpected error occurred. Please try again later." });
  }
});

// 📌 **Reset Password Route**
app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    console.log("🔐 Password reset attempt with token");

    if (!token || !newPassword) {
      return res
        .status(400)
        .json({ error: "Token and new password are required." });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters long." });
    }

    // Verify reset token
    let decoded;
    try {
      decoded = jwt.verify(token, RESET_TOKEN_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(400)
          .json({ error: "Reset link has expired. Please request a new one." });
      }
      return res.status(400).json({ error: "Invalid reset token." });
    }

    if (decoded.purpose !== "password_reset") {
      return res.status(400).json({ error: "Invalid token purpose." });
    }

    // Find user
    const UserModel = createUserModel(decoded.userName);
    const user = await UserModel.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await UserModel.findByIdAndUpdate(decoded.id, {
      password: hashedPassword,
    });

    console.log("✅ Password reset successful for user:", decoded.userName);
    res.status(200).json({ message: "Password has been reset successfully." });
  } catch (error) {
    console.error("❌ Error in reset password:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Verify Reset Token Route** (Optional - for frontend validation)
app.post("/api/verify-reset-token", async (req, res) => {
  const { token } = req.body;

  try {
    if (!token) {
      return res.status(400).json({ error: "Token is required." });
    }

    // Verify token
    const decoded = jwt.verify(token, RESET_TOKEN_SECRET);

    if (decoded.purpose !== "password_reset") {
      return res.status(400).json({ error: "Invalid token purpose." });
    }

    res.status(200).json({
      message: "Token is valid.",
      email: decoded.email,
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({ error: "Reset link has expired." });
    }
    return res.status(400).json({ error: "Invalid token." });
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

// Add a new investment
app.post("/investment", verifyToken, async (req, res) => {
  try {
    console.log("💰 Creating investment for user:", req.user.id);
    console.log("💰 Investment data:", req.body);

    const investmentData = req.body;
    // Add user ID from the token (convert to ObjectId)
    investmentData.user = new mongoose.Types.ObjectId(req.user.id);

    // Set currentAmount equal to initial amount for new investments
    investmentData.currentAmount = investmentData.amount;

    // IMPORTANT FIX: Provide a default name if it's a "Savings" type and no name is provided
    if (investmentData.investmentType === "Savings" && !investmentData.name) {
      investmentData.name = "General Savings"; // Or "Savings Account" + a timestamp, etc.
    }

    const newInvestment = new Investment(investmentData);
    await newInvestment.save();
    console.log("✅ Investment created successfully:", newInvestment._id);
    res.json(newInvestment);
  } catch (err) {
    console.error("❌ Error creating investment:", err);
    res.status(500).json({ error: err.message || "Failed to add investment" });
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
    const userId = new mongoose.Types.ObjectId(req.user.id);
    const investmentCount = await Investment.countDocuments({ user: userId });
    console.log("🧪 Investment count for user:", investmentCount);

    res.json({
      message: "Token is valid",
      user: req.user,
      userExistsInDB: !!user,
      investmentCount,
      userIdType: typeof req.user.id,
      userIdAsObjectId: userId.toString(),
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

// 📌 Debug endpoint to check stored user info format
app.get("/debug-login", async (req, res) => {
  try {
    res.json({
      message: "Debug login endpoint",
      jwtSecret: JWT_SECRET ? "Available" : "Missing",
      jwtSecretSample: JWT_SECRET
        ? JWT_SECRET.substring(0, 10) + "..."
        : "None",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all investments
app.get("/investments", verifyToken, async (req, res) => {
  try {
    console.log("📊 Getting investments for user:", req.user.id);
    console.log("📊 User object:", req.user);

    // Convert string ID to ObjectId if needed
    const userId = new mongoose.Types.ObjectId(req.user.id);
    const investments = await Investment.find({ user: userId });
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
    const userId = new mongoose.Types.ObjectId(req.user.id);
    const investment = await Investment.findOne({
      _id: req.params.id,
      user: userId,
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

// Delete investment
app.delete("/investment/:id", verifyToken, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.user.id);
    const investment = await Investment.findOne({
      _id: req.params.id,
      user: userId,
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

// Manually trigger interest calculation (for testing)
app.post("/calculate-interest", verifyToken, async (req, res) => {
  try {
    await updateDailyInterest();
    res.json({ message: "Interest calculation triggered successfully" });
  } catch (err) {
    res.status(500).json(err);
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
