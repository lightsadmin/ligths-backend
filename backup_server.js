require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// ObjectId is not explicitly used in the provided selection, so removed for brevity.
// const ObjectId = mongoose.Types.ObjectId;

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://subikshapc:<db_password>@ligths.tncb6.mongodb.net/?retryWrites=true&w=majority&appName=Ligths";

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// 🔹 **MongoDB Connection**
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// 📌 Define Goal Schema (Re-introduced for GoalCalculator module)
const goalSchema = new mongoose.Schema({
  userName: { type: String, required: true }, // Link to the user who owns this goal
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
  const collectionName = `${userName}_details`;

  console.log(`🔍 Creating model for collection: ${collectionName}`);

  // ✅ Check if model already exists
  if (mongoose.models[collectionName]) {
    console.log(`✅ Using existing model for: ${collectionName}`);
    return mongoose.models[collectionName];
  }

  const UserSchema = new mongoose.Schema(
    {
      type: { type: String, enum: ["User"], required: true },
      firstName: { type: String },
      lastName: { type: String },
      userName: {
        type: String,
        minlength: [2, "❌ Username must be at least 2 characters long."],
      },
      email: { type: String, unique: true },
      password: { type: String },
      age: { type: Number },
      retirementAge: { type: Number },
      phoneNumber: { type: String },
      country: { type: String },

      // Transaction Array
      transactions: [
        {
          name: { type: String },
          amount: { type: Number },
          type: { type: String, enum: ["Income", "Investment", "Expense"] },
          subType: { type: String },
          method: { type: String },
          date: { type: String },
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
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    const collectionExists = collections.some(
      (col) => col.name === `${userName}_details`
    );

    if (collectionExists) {
      const UserModel = createUserModel(userName);
      const existingUser = await UserModel.findOne({ userName, type: "User" });

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
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();

    for (const col of collections) {
      // Dynamically create a model for each collection to query it
      const UserModel = mongoose.model(
        col.name,
        new mongoose.Schema({}, { strict: false }),
        col.name
      );
      const existingUser = await UserModel.findOne({ email, type: "User" });

      if (existingUser) {
        return res.status(200).json({ exists: true });
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

    // Check if the username already exists in the database
    const collections = await mongoose.connection.db
      .listCollections()
      .toArray();
    const existingCollection = collections.some(
      (col) => col.name === `${userName}_details`
    );

    if (existingCollection) {
      const UserModel = createUserModel(userName);
      const existingUser = await UserModel.findOne({ userName, type: "User" });
      if (existingUser) {
        return res.status(400).json({ error: "Username already taken!" });
      }
    }

    // Create a hashed password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User Model for the new user
    const UserModel = createUserModel(userName);
    const newUser = new UserModel({
      type: "User",
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

    // Save User as a new document
    await newUser.save();

    const token = jwt.sign(
      { userId: newUser._id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(201).json({ message: "User registered successfully!", token });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Login Route**
app.post("/api/login", async (req, res) => {
  const { userName, password } = req.body;

  try {
    if (!userName || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }

    // Fetch user collection dynamically
    const UserModel = createUserModel(userName);
    const user = await UserModel.findOne({ userName, type: "User" });

    if (!user) {
      return res.status(400).json({ error: "User not found!" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password!" });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({
      token,
      user: {
        firstName: user.firstName,
        email: user.email,
        userName: user.userName,
      },
    }); // Added userName to user object
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Get User Profile Route**
app.get("/profile/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const UserModel = createUserModel(userName);
    const user = await UserModel.findOne({ userName, type: "User" }).select(
      "-password"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Add Transaction to User's Transactions Array**
app.post("/transactions/:userName", async (req, res) => {
  const { userName } = req.params;
  const { name, amount, type, subType, method, date } = req.body;

  try {
    const UserModel = createUserModel(userName);

    // Check if the user exists
    const user = await UserModel.findOne({ userName, type: "User" });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    // Push new transaction into the transactions array
    user.transactions.push({
      name,
      amount,
      type,
      subType,
      method,
      date,
    });

    // Save the updated document
    await user.save();

    res.status(201).json({ message: "Transaction added successfully!" });
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

    // Find the user and return only transactions
    const user = await UserModel.findOne({ userName, type: "User" });
    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user.transactions);
  } catch (err) {
    console.error("Error fetching transactions:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 📌 **Get All User and Transaction Data Together**
app.get("/all-data/:userName", async (req, res) => {
  const { userName } = req.params;

  try {
    const UserModel = createUserModel(userName);

    // Get user with all transactions
    const user = await UserModel.findOne({ userName, type: "User" }).select(
      "-password"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found!" });
    }

    res.json(user);
  } catch (err) {
    console.error("Error fetching all data:", err);
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
    console.error(`Error creating goal for ${username}:`, error.stack);
    if (error.name === "ValidationError") {
      console.error("Mongoose Validation errors:", error.errors);
      const errors = Object.keys(error.errors).map(
        (key) => error.errors[key].message
      );
      return res
        .status(400)
        .json({ error: `Validation failed: ${errors.join(", ")}` });
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
      { new: true } // Return the updated document
    );

    if (!updatedGoal) {
      return res
        .status(404)
        .json({ error: "Goal not found or not authorized for this user." });
    }

    res.status(200).json(updatedGoal);
  } catch (error) {
    console.error("Error updating goal:", error);
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

// 🔹 **Start Server**
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
