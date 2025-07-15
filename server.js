require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require('google-auth-library'); // For Google Auth verification
const ObjectId = mongoose.Types.ObjectId; // Keep ObjectId for transaction deletion

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://subikshapc:<db_password>@ligths.tncb6.mongodb.net/?retryWrites=true&w=majority&appName=Ligths";

// CRITICAL CHECK: Ensure the MONGO_URI placeholder is replaced
if (MONGO_URI.includes("<db_password>")) {
  console.error(
    "CRITICAL ERROR: MONGO_URI still contains the placeholder '<db_password>'. Please replace it with your actual MongoDB password or set it in your environment variables on Render."
  );
  // In a production environment, you might want to exit the process here
  // process.exit(1);
}

// Google OAuth Client ID for backend verification
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '127526920655-8uujrvt9ul3jnl36kadgurpegd1lj74p.apps.googleusercontent.com'; // Use your actual web client ID
const client = new OAuth2Client(GOOGLE_CLIENT_ID);


const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// 🔹 **MongoDB Connection**
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
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
  user: { type: mongoose.Schema.Types.ObjectId, required: true }, // Link to the user's _id
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
  userName: { type: String, required: true }, // Link to the user who owns this goal (their unique username)
  name: { type: String, required: true }, // e.g., "B Education", "Dream Home", "Custom Goal"
  customName: { type: String }, // For custom goals
  presentCost: { type: Number, required: true },
  childCurrentAge: { type: Number },
  goalAge: { type: Number },
  years: { type: Number }, // Years to reach the goal
  currentAge: { type: Number },
  inflation: { type: Number, default: 7.5 },
  returnRate: { type: Number, required: true },
  currentSip: { type: Number, default: 0 }, // In-hand value / existing lumpsum
  investmentType: { type: String, default: "SIP/MF" },
  futureCost: { type: Number },
  required: { type: Number }, // Amount still needed
  futureValueOfSavings: { type: Number }, // Future value of in-hand amount
  monthlySIP: { type: Number }, // Additional monthly SIP required
  calculatedAt: { type: String }, // Timestamp of last calculation
  createdAt: { type: Date, default: Date.now }, // When the goal was first created
});

const Goal = mongoose.model("Goal", goalSchema);

// 🔹 **Create User Model Dynamically**
const createUserModel = (userName) => {
  // Collection name now explicitly includes '_details' suffix for consistency with existing files
  const collectionName = `${userName}_details`;

  console.log(`🔍 Creating model for collection: ${collectionName}`);

  // ✅ Check if model already exists
  if (mongoose.models[collectionName]) {
    console.log(`✅ Using existing model for: ${collectionName}`);
    return mongoose.models[collectionName];
  }

  const UserSchema = new mongoose.Schema(
    {
      type: { type: String, enum: ["User"], default: "User" }, // Default to "User"
      firstName: { type: String },
      lastName: { type: String },
      userName: {
        type: String,
        minlength: [2, "❌ Username must be at least 2 characters long."],
        required: true,
        unique: true, // Ensure userName is unique within this collection
      },
      email: { type: String, unique: true, required: true },
      password: { type: String }, // Password can be optional for Google users
      age: { type: Number },
      retirementAge: { type: Number },
      phoneNumber: { type: String },
      country: { type: String },
      googleId: { type: String, unique: true, sparse: true }, // For Google Auth
      picture: { type: String }, // Google profile picture

      // Transaction Array (embedded documents)
      transactions: [
        {
          name: { type: String, required: true },
          amount: { type: Number, required: true },
          type: { type: String, enum: ["Income", "Investment", "Expense"], required: true },
          subType: { type: String },
          method: { type: String, required: true },
          date: { type: String, required: true },
          createdAt: { type: Date, default: Date.now },
        },
      ],
    },
    { timestamps: true }
  );

  console.log(`✅ Creating new model for: ${collectionName}`);
  return mongoose.model(collectionName, UserSchema, collectionName);
};

// 📌 **Check if Username Exists**
app.get("/check-username/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionExists = collections.some(
      (col) => col.name === `${userName}_details`
    );

    if (collectionExists) {
      const UserModel = createUserModel(userName);
      const existingUser = await UserModel.findOne({ userName }); // No need for type: "User" here as it's default
      if (existingUser) {
        return res.status(200).json({ exists: true });
      }
    }
    res.status(200).json({ exists: false });
  } catch (err) {
    console.error("Error checking username:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Check if Email Exists**
app.get("/check-email/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const collections = await mongoose.connection.db.listCollections().toArray();

    for (const col of collections) {
      // Dynamically create a model for each collection to query it
      // Use a generic schema for checking email across all user collections.
      // Ensure we only query user-specific collections (ending with _details)
      if (col.name.endsWith('_details')) {
        const UserModel = mongoose.model(col.name, new mongoose.Schema({}, { strict: false }), col.name);
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
          return res.status(200).json({ exists: true });
        }
      }
    }
    res.status(200).json({ exists: false });
  } catch (err) {
    console.error("Error checking email:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Register Route**
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

    // Check if the username collection already exists
    const collections = await mongoose.connection.db.listCollections().toArray();
    const existingCollection = collections.some(
      (col) => col.name === `${userName}_details`
    );

    if (existingCollection) {
      const UserModel = createUserModel(userName);
      const existingUser = await UserModel.findOne({ userName });
      if (existingUser) {
        return res.status(400).json({ error: "Username already taken!" });
      }
    }

    // Hash password
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
      transactions: [],
    });

    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, userName: newUser.userName },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.status(201).json({
      message: "User registered successfully!",
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
  } catch (error) {
    console.error("Error during registration:", error);
    if (error.code === 11000) {
      return res.status(409).json({ error: "Email or Username already exists." });
    }
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Login Route**
app.post("/api/login", async (req, res) => {
  const { identifier, password } = req.body; // 'identifier' can be username or email

  try {
    let user = null;
    let UserModel = null;

    // First, try to find user by username (collection name)
    const usernameCollectionName = `${identifier}_details`;
    if (mongoose.models[usernameCollectionName]) {
      UserModel = createUserModel(identifier);
      user = await UserModel.findOne({ userName: identifier });
    }

    // If not found by username, try to find by email across all existing user collections
    if (!user) {
      const collections = await mongoose.connection.db.listCollections().toArray();
      for (const col of collections) {
        if (col.name.endsWith('_details')) { // Only check user-specific collections
          const PotentialUserModel = createUserModel(col.name.replace('_details', ''));
          const foundUser = await PotentialUserModel.findOne({ email: identifier });
          if (foundUser) {
            user = foundUser;
            UserModel = PotentialUserModel; // Set UserModel for consistent access
            break;
          }
        }
      }
    }

    if (!user) {
      return res.status(400).json({ error: "Invalid Credentials!" });
    }

    // Compare password (only if user has a password set)
    if (user.password) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: "Invalid Credentials!" });
      }
    } else {
      // If no password, it means it's likely a Google-registered user
      return res.status(400).json({ error: "Please use Google Sign-In for this account." });
    }

    const token = jwt.sign({ id: user._id, userName: user.userName }, JWT_SECRET, { expiresIn: "7d" });
    res.json({
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
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Google Authentication Route**
app.post("/api/google-login", async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: "ID token is required." });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check if user already exists by googleId or email
    let user = null;
    let UserModel = null;

    // Try to find by Google ID across all user collections
    const collections = await mongoose.connection.db.listCollections().toArray();
    for (const col of collections) {
      if (col.name.endsWith('_details')) {
        const PotentialUserModel = createUserModel(col.name.replace('_details', ''));
        const foundUser = await PotentialUserModel.findOne({ googleId });
        if (foundUser) {
          user = foundUser;
          UserModel = PotentialUserModel;
          break;
        }
      }
    }

    // If not found by Google ID, try to find by email
    if (!user) {
      for (const col of collections) {
        if (col.name.endsWith('_details')) {
          const PotentialUserModel = createUserModel(col.name.replace('_details', ''));
          const foundUser = await PotentialUserModel.findOne({ email });
          if (foundUser) {
            user = foundUser;
            UserModel = PotentialUserModel;
            break;
          }
        }
      }
    }

    if (user) {
      // User exists, update Google ID if not already set
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }
      console.log("Existing user logged in via Google:", user.userName);
    } else {
      // New user, create a new entry
      const newUserName = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, ''); // Simple username from email
      // Ensure uniqueness for generated username
      let finalUserName = newUserName;
      let counter = 0;
      let userNameExists = true;
      while(userNameExists) {
        const checkCollections = await mongoose.connection.db.listCollections().toArray();
        const exists = checkCollections.some(col => col.name === `${finalUserName}_details`);
        if (!exists) {
          userNameExists = false;
        } else {
          counter++;
          finalUserName = `${newUserName}${counter}`;
        }
      }

      UserModel = createUserModel(finalUserName);
      user = new UserModel({
        firstName: name.split(' ')[0] || 'Google',
        lastName: name.split(' ').slice(1).join(' ') || 'User',
        userName: finalUserName,
        email: email,
        googleId: googleId,
        picture: picture,
        transactions: [],
        type: "User", // Explicitly set type for new users
      });
      await user.save();
      console.log("New user registered via Google:", user.userName);
    }

    const token = jwt.sign({ id: user._id, userName: user.userName }, JWT_SECRET, { expiresIn: "7d" });
    res.status(200).json({
      token,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.userName,
        email: user.email,
        picture: user.picture,
      },
    });

  } catch (error) {
    console.error("Google Auth Error:", error.message);
    res.status(500).json({ error: "Google authentication failed." });
  }
});


// 📌 **JWT Token Verification Middleware**
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // decoded will contain { id: user._id, userName: user.userName }
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
};

// 📌 **Get User Profile Route**
app.get("/profile/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const UserModel = createUserModel(userName);
    const user = await UserModel.findOne({ userName }).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Update User Profile Route**
app.put("/profile/:userName", async (req, res) => {
  try {
    const { userName } = req.params;
    const updateData = req.body;

    if (!updateData.firstName || !updateData.lastName) {
      return res
        .status(400)
        .json({ error: "First name and last name are required." });
    }

    const UserModel = createUserModel(userName);
    const user = await UserModel.findOne({ userName });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

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

    await user.save();

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


// 📌 **Add Transaction to User's Transactions Array**
app.post("/transactions/:userName", async (req, res) => {
  const { userName } = req.params;
  const { name, amount, type, subType, method, date } = req.body;

  try {
    const UserModel = createUserModel(userName);

    const user = await UserModel.findOne({ userName });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    user.transactions.push({
      name,
      amount,
      type,
      subType,
      method,
      date,
    });

    await user.save();

    const addedTransaction = user.transactions[user.transactions.length - 1];
    res.status(201).json({ message: "Transaction added successfully!", transaction: addedTransaction });
  } catch (err) {
    console.error("Error adding transaction:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Get All Transactions of User**
app.get("/transactions/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const UserModel = createUserModel(userName);

    const user = await UserModel.findOne({ userName });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user.transactions);
  } catch (err) {
    console.error("Error fetching transactions:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Delete Transaction from User's Transactions Array**
app.delete("/transactions/:username/:id", async (req, res) => {
  const { username, id } = req.params;
  console.log(`🗑️ Deleting transaction with ID: ${id} for user: ${username}`);

  try {
    const UserModel = createUserModel(username);

    if (!ObjectId.isValid(id)) {
      console.log("❗ Invalid ObjectId format");
      return res.status(400).json({ error: "Invalid transaction ID." });
    }

    const user = await UserModel.findOne({ userName: username });

    if (!user) {
      console.log(`❗ User ${username} not found.`);
      return res.status(404).json({ error: "User not found." });
    }

    const initialTransactionCount = user.transactions.length;
    user.transactions = user.transactions.filter(
      (transaction) => transaction._id.toString() !== id
    );

    if (user.transactions.length === initialTransactionCount) {
      console.log("❌ Transaction not found for deletion.");
      return res.status(404).json({ error: "Transaction not found." });
    }

    await user.save();

    console.log(`✅ Transaction deleted successfully!`);
    res
      .status(200)
      .json({ success: true, message: "Transaction deleted successfully." });
  } catch (error) {
    console.error("❌ Error deleting transaction:", error);
    res.status(500).json({ error: "Error deleting transaction." });
  }
});


// 📌 **Get All User and Transaction Data Together**
app.get("/all-data/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const UserModel = createUserModel(userName);

    const user = await UserModel.findOne({ userName }).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user);
  } catch (err) {
    console.error("Error fetching all data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Inflation Data Route**
app.get("/api/inflation-data", (req, res) => {
  try {
    // Assuming inflation_data.json exists in the same directory as server.js
    // If you don't have this file, this route will fail. Consider mocking or removing.
    const inflationData = require("./inflation_data.json");
    res.json(inflationData);
  } catch (error) {
    console.error("Error loading inflation data:", error);
    res.status(500).json({ error: "Failed to retrieve inflation data" });
  }
});

// 📌 **Monthly Essential Expenses Calculation**
app.get("/transactions/:username/monthly-essential", async (req, res) => {
  const { username } = req.params;
  const { includeToday } = req.query;

  try {
    const UserModel = createUserModel(username);
    const user = await UserModel.findOne({ userName: username });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

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

    const today = new Date();
    const todayString = `${today.getFullYear()}-${String(
      today.getMonth() + 1
    ).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;

    const validExpenses = essentialExpenses.filter((expense) => {
      try {
        const date = new Date(expense.date);
        return (
          !isNaN(date) &&
          date.getFullYear() >= 2000 &&
          (includeToday === "true" || expense.date !== todayString)
        );
      } catch (e) {
        return false;
      }
    });

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

    const totalAmount = validExpenses.reduce(
      (sum, expense) => sum + expense.amount,
      0
    );

    const uniqueDays = new Set(
      validExpenses.map((expense) => expense.date.substring(0, 10))
    ).size;

    const sortedExpenses = [...validExpenses].sort(
      (a, b) => new Date(a.date) - new Date(b.date)
    );

    const earliestDate = new Date(sortedExpenses[0].date);
    const latestDate = new Date(sortedExpenses[sortedExpenses.length - 1].date);

    const monthsSpan =
      (latestDate.getFullYear() - earliestDate.getFullYear()) * 12 +
      (latestDate.getMonth() - earliestDate.getMonth()) +
      1;

    const avgPerDay = totalAmount / uniqueDays;
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


// 📌 **Function to update daily interest for all investments**
const updateDailyInterest = async () => {
  try {
    const investments = await Investment.find({});

    for (const investment of investments) {
      const now = new Date();
      const lastUpdate = new Date(investment.lastInterestUpdate);

      const daysDiff = Math.floor((now - lastUpdate) / (1000 * 60 * 60 * 24));

      if (daysDiff > 0) {
        const dailyRate = investment.interestRate / 100 / 365;
        const newAmount =
          investment.currentAmount * Math.pow(1 + dailyRate, daysDiff);

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


// 📌 **Investment Routes**

// Add a new investment
app.post("/investment", verifyToken, async (req, res) => {
  try {
    const investmentData = req.body;
    // Add user ID from the token
    investmentData.user = req.user.id; // req.user.id is the _id of the user document

    // Set currentAmount equal to initial amount for new investments
    investmentData.currentAmount = investmentData.amount;

    const newInvestment = new Investment(investmentData);
    await newInvestment.save();
    res.json(newInvestment);
  } catch (err) {
    console.error("Error adding investment:", err);
    res.status(500).json(err);
  }
});

// Get all investments for the authenticated user
app.get("/investments", verifyToken, async (req, res) => {
  try {
    const investments = await Investment.find({ user: req.user.id });
    res.json(investments);
  }
  catch (err) {
    console.error("Error fetching investments:", err);
    res.status(500).json(err);
  }
});

// Update investment for the authenticated user
app.put("/investment/:id", verifyToken, async (req, res) => {
  try {
    const investment = await Investment.findOne({
      _id: req.params.id,
      user: req.user.id, // Ensure user owns the investment
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
    console.error("Error updating investment:", err);
    res.status(500).json(err);
  }
});

// Delete investment for the authenticated user
app.delete("/investment/:id", verifyToken, async (req, res) => {
  try {
    const investment = await Investment.findOne({
      _id: req.params.id,
      user: req.user.id, // Ensure user owns the investment
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

// Get investments by goal (placeholder for future integration)
// This route is a placeholder. If you have an actual "goalId" in your investments,
// you would filter by that here. For now, it returns empty data.
app.get("/investments/:username/by-goal/:goalId", async (req, res) => {
  const { username, goalId } = req.params;

  try {
    // In a real scenario, you might have a 'goalId' field in your Investment schema
    // and would query based on that. For this setup, it's a placeholder.
    // const investmentsForGoal = await Investment.find({ user: req.user.id, goalId: goalId });
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

// 📌 **Goal Routes (for GoalCalculator module)**

// Get all goals for a specific user
app.get("/goals/:username", async (req, res) => {
  const { username } = req.params;

  try {
    // Find goals associated with the provided username
    const goals = await Goal.find({ userName: username }).sort({
      createdAt: -1,
    });
    res.status(200).json(goals);
  } catch (error) {
    console.error("Error fetching goals:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Create a new goal for a user
app.post("/goals/:username", async (req, res) => {
  const { username } = req.params;
  const goalData = req.body;

  console.log(`Received goal data for ${username}:`, goalData);

  try {
    // Validate required fields
    const requiredFields = ["name", "presentCost", "returnRate"];
    const missingFields = requiredFields.filter((field) => {
      if (goalData[field] === null || goalData[field] === undefined) {
        return true;
      }
      if (
        typeof goalData[field] === "string" &&
        goalData[field].trim() === ""
      ) {
        return true;
      }
      return false;
    });

    if (missingFields.length > 0) {
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
      "futureCost",
      "required",
      "futureValueOfSavings",
      "monthlySIP",
    ];
    for (const field of numericFields) {
      if (
        goalData[field] !== undefined &&
        goalData[field] !== null &&
        isNaN(parseFloat(goalData[field]))
      ) {
        return res
          .status(400)
          .json({ error: `${field} must be a valid number` });
      }
    }

    // Create the new goal object, associating it with the username
    const newGoal = new Goal({
      userName: username, // Assign the username from the URL parameter
      name: goalData.name,
      customName: goalData.customName || undefined,
      presentCost: parseFloat(goalData.presentCost),
      childCurrentAge: goalData.childCurrentAge
        ? parseFloat(goalData.childCurrentAge)
        : undefined,
      goalAge: goalData.goalAge ? parseFloat(goalData.goalAge) : undefined,
      years: goalData.years ? parseFloat(goalData.years) : undefined,
      currentAge: goalData.currentAge
        ? parseFloat(goalData.currentAge)
        : undefined,
      inflation: parseFloat(goalData.inflation || 7.5),
      returnRate: parseFloat(goalData.returnRate),
      currentSip: parseFloat(goalData.currentSip || 0),
      investmentType: goalData.investmentType || "SIP/MF",
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
      calculatedAt: new Date().toLocaleString(),
    });

    const savedGoal = await newGoal.save();
    res.status(201).json(savedGoal);
  } catch (error) {
    // Enhanced error logging for goal creation
    console.error(`Error creating goal for ${username}:`, error.message);
    console.error("Error name:", error.name);
    console.error("Error stack:", error.stack);

    if (error.name === "ValidationError") {
      console.error("Mongoose Validation errors:", error.errors);
      const errors = Object.keys(error.errors).map(
        (key) => error.errors[key].message
      );
      return res
        .status(400)
        .json({ error: `Validation failed: ${errors.join(", ")}` });
    } else if (error.code === 11000) {
      // MongoDB duplicate key error
      console.error("MongoDB duplicate key error:", error.message);
      return res.status(409).json({
        error:
          "A goal with similar unique properties already exists. Please check your input.",
      });
    } else if (error.name === "MongoError") {
      console.error("MongoDB error:", error.message);
      return res
        .status(500)
        .json({ error: "Database operation failed. Please try again." });
    }
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Update a goal for a specific user
app.put("/goals/:username/:id", async (req, res) => {
  const { username, id } = req.params;
  const updateData = req.body;

  try {
    const updatedGoal = await Goal.findOneAndUpdate(
      { _id: id, userName: username }, // Find by ID and username to ensure ownership
      { ...updateData, calculatedAt: new Date().toLocaleString() },
      { new: true, runValidators: true } // Return the updated document and run validators
    );

    if (!updatedGoal) {
      return res
        .status(404)
        .json({ error: "Goal not found or not authorized for this user." });
    }

    res.status(200).json(updatedGoal);
  } catch (error) {
    console.error("Error updating goal:", error);
    if (error.name === "ValidationError") {
      const errors = Object.keys(error.errors).map(
        (key) => error.errors[key].message
      );
      return res
        .status(400)
        .json({ error: `Validation failed: ${errors.join(", ")}` });
    }
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Delete a goal for a specific user
app.delete("/goals/:username/:id", async (req, res) => {
  const { username, id } = req.params;

  try {
    const deletedGoal = await Goal.findOneAndDelete({
      _id: id,
      userName: username, // Ensure only the owner can delete
    });

    if (!deletedGoal) {
      return res
        .status(404)
        .json({ error: "Goal not found or not authorized for this user." });
    }

    res.status(200).json({ message: "Goal deleted successfully" });
  } catch (error) {
    console.error("Error deleting goal:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 Get All Goals (public) - This route is redundant if goals are user-specific, consider removing if not needed.
// Keeping it for now as it was in your original server.js
app.get("/goals", async (req, res) => {
  try {
    const allGoals = await Goal.find({});
    res.json(allGoals);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch all goals" });
  }
});

// 🔹 **Start Server**
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

