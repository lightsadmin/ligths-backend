require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const ObjectId = mongoose.Types.ObjectId;


const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";
const MONGO_URI =  process.env.MONGO_URI || "mongodb+srv://subikshapc:<db_password>@ligths.tncb6.mongodb.net/?retryWrites=true&w=majority&appName=Ligths";

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// 🔹 **MongoDB Connection**
mongoose
  .connect(process.env.MONGO_URI)
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
  description: { type: String }
});

const Investment = mongoose.model("Investment", investmentSchema);

// 📌 Define Goal Schema
const goalSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  name: { type: String, required: true },
  customName: { type: String },
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
  createdAt: { type: Date, default: Date.now }
});

const Goal = mongoose.model("Goal", goalSchema);

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
        type: { type: String, required: true, enum: ["Income", "Investment", "Expense"] },
        subType: { type: String, required: function () { return this.type === "Expense"; } },
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
    const collections = await mongoose.connection.db.listCollections().toArray();
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
    const collections = await mongoose.connection.db.listCollections().toArray();
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
      return res.status(400).json({ error: "First name and last name are required." });
    }

    // Create user model
    const UserModel = createUserModel(userName);
    
    // Find user
    const user = await UserModel.findOne({ userName });
    
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    
    // Update allowed fields only (prevent updating sensitive fields like password)
    const allowedFields = ['firstName', 'lastName', 'phoneNumber', 'country', 'age', 'retirementAge'];
    
    allowedFields.forEach(field => {
      if (updateData[field] !== undefined) {
        // Convert age and retirementAge to numbers if they are provided
        if ((field === 'age' || field === 'retirementAge') && updateData[field]) {
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
      retirementAge: user.retirementAge
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

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

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
    const collections = await mongoose.connection.db.listCollections().toArray();
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
    return res.status(400).json({ error: "Please enter a valid email address" });
  }

  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
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
      console.log(`⚠️ Found ${invalidTransactions.length} invalid transactions. Fixing them...`);
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
    res.status(200).json({ success: true, message: "Transaction deleted successfully." });
  } catch (error) {
    console.error("❌ Error deleting transaction:", error);
    res.status(500).json({ error: "Error deleting transaction." });
  }
});



app.get("/api/inflation-data", (req, res) => {
  try {
    const inflationData = require('./inflation_data.json');
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
      transaction => transaction.type === "Expense" && transaction.subType === "Essential"
    );

    if (essentialExpenses.length === 0) {
      return res.json({
        monthlyAverage: "0.00",
        dailyAverage: "0.00",
        days: 0,
        months: 0,
        totalAmount: 0,
        expenses: []
      });
    }

    // Get today's date in YYYY-MM-DD format
    const today = new Date();
    const todayString = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;

    // Verify dates and filter out invalid ones (but include today if requested)
    const validExpenses = essentialExpenses.filter(expense => {
      try {
        const date = new Date(expense.date);
        // Filter out invalid dates, but conditionally include today's expenses
        return !isNaN(date) && 
               date.getFullYear() >= 2000 &&
               (includeToday === 'true' || expense.date !== todayString);
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
        expenses: []
      });
    }

    // Calculate total amount
    const totalAmount = validExpenses.reduce((sum, expense) => sum + expense.amount, 0);
    
    // Count unique days of expenses
    const uniqueDays = new Set(validExpenses.map(expense => expense.date.substring(0, 10))).size;
    
    // Sort expenses by date
    const sortedExpenses = [...validExpenses].sort((a, b) => 
      new Date(a.date) - new Date(b.date)
    );
    
    const earliestDate = new Date(sortedExpenses[0].date);
    const latestDate = new Date(sortedExpenses[sortedExpenses.length - 1].date);
    
    // Calculate months span for informational purposes
    const monthsSpan = 
      (latestDate.getFullYear() - earliestDate.getFullYear()) * 12 + 
      (latestDate.getMonth() - earliestDate.getMonth()) + 1;
    
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
      calculationMethod: "Total expenses ÷ unique days with expenses × 30 days"
    });
  } catch (err) {
    console.error("Error calculating monthly expenses:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// 📌 JWT Token Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  
  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
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
        const newAmount = investment.currentAmount * Math.pow(1 + dailyRate, daysDiff);
        
        // Update the investment
        await Investment.findByIdAndUpdate(investment._id, {
          currentAmount: newAmount,
          lastInterestUpdate: now
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

// Get all goals for a user
// In server.js

// ... existing imports and code ...

app.post("/goals/:username", async (req, res) => {
  const { username } = req.params;
  const goalData = req.body;

  console.log(`Received goal data for ${username}:`, goalData);

  try {
    // Validate required fields
    const requiredFields = ["name", "presentCost", "returnRate"];
    const missingFields = requiredFields.filter((field) => !goalData[field]);
    if (missingFields.length > 0) {
      return res
        .status(400)
        .json({ error: `Missing required fields: ${missingFields.join(", ")}` });
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
    for (const field of numericFields) {
      // Only validate if the field exists in goalData and is not a valid number
      if (goalData[field] !== undefined && goalData[field] !== null && isNaN(parseFloat(goalData[field]))) {
        return res.status(400).json({ error: `${field} must be a valid number` });
      }
    }

    // Explicitly create the new goal object, parsing values and handling defaults/optionality
    const newGoal = new Goal({
      userName: username,
      name: goalData.name,
      customName: goalData.customName || undefined, // Set to undefined if empty string or null
      presentCost: parseFloat(goalData.presentCost),
      // Handle optional fields: if they exist, parse them, otherwise leave undefined/null
      childCurrentAge: goalData.childCurrentAge ? parseFloat(goalData.childCurrentAge) : undefined,
      goalAge: goalData.goalAge ? parseFloat(goalData.goalAge) : undefined,
      years: goalData.years ? parseFloat(goalData.years) : undefined,
      currentAge: goalData.currentAge ? parseFloat(goalData.currentAge) : undefined,
      inflation: parseFloat(goalData.inflation || 7.5), // Use default if frontend doesn't send
      returnRate: parseFloat(goalData.returnRate),
      currentSip: parseFloat(goalData.currentSip || 0), // Use default if frontend sends empty/null
      investmentType: goalData.investmentType || "SIP/MF",
      // Include calculated fields from frontend
      futureCost: goalData.futureCost ? parseFloat(goalData.futureCost) : undefined,
      required: goalData.required ? parseFloat(goalData.required) : undefined,
      futureValueOfSavings: goalData.futureValueOfSavings ? parseFloat(goalData.futureValueOfSavings) : undefined,
      monthlySIP: goalData.monthlySIP ? parseFloat(goalData.monthlySIP) : undefined,
      calculatedAt: new Date().toLocaleString(), // Server-side timestamp
      // createdAt is handled by Mongoose default
    });

    const savedGoal = await newGoal.save();
    res.status(201).json(savedGoal);
  } catch (error) {
    console.error(`Error creating goal for ${username}:`, error.stack); // This is key for debugging on server logs
    if (error.name === "ValidationError") {
      // Mongoose validation error (e.g., required field missing, type mismatch)
      console.error("Mongoose Validation errors:", error.errors);
      // Construct a more user-friendly error message from Mongoose validation errors
      const errors = Object.keys(error.errors).map(key => error.errors[key].message);
      return res.status(400).json({ error: `Validation failed: ${errors.join(", ")}` });
    } else if (error.name === "MongoError") {
      // MongoDB specific error (e.g., connection issue, duplicate key)
      console.error("MongoDB error:", error.message);
      return res.status(500).json({ error: "Database operation failed. Please try again." });
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
      { ...updateData, calculatedAt: new Date().toLocaleString() },
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
    const deletedGoal = await Goal.findOneAndDelete({ _id: id, userName: username });
    
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
      investments: []
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
        const investmentData = req.body;
        // Add user ID from the token
        investmentData.user = req.user.id;
        
        // Set currentAmount equal to initial amount for new investments
        investmentData.currentAmount = investmentData.amount;
        
        const newInvestment = new Investment(investmentData);
        await newInvestment.save();
        res.json(newInvestment);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get all investments
app.get("/investments", verifyToken, async (req, res) => {
    try {
        const investments = await Investment.find({ user: req.user.id });
        res.json(investments);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Update investment
app.put("/investment/:id", verifyToken, async (req, res) => {
    try {
        const investment = await Investment.findOne({ 
            _id: req.params.id,
            user: req.user.id
        });
        
        if (!investment) {
            return res.status(404).json({ error: "Investment not found or not authorized" });
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
        const investment = await Investment.findOne({ 
            _id: req.params.id,
            user: req.user.id
        });
        
        if (!investment) {
            return res.status(404).json({ error: "Investment not found or not authorized" });
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
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
