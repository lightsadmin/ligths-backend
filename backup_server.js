require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

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

// 🔹 **Create User Model Dynamically**
const createUserModel = (userName) => {
  const collectionName = `${userName}_details`;

  // ✅ Check if model already exists
  if (mongoose.models[collectionName]) {
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
    const collections = await mongoose.connection.db.listCollections().toArray();

    for (const col of collections) {
      const UserModel = mongoose.model(col.name, {}, col.name);
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
    const collections = await mongoose.connection.db.listCollections().toArray();
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
    res.json({ token, user: { firstName: user.firstName, email: user.email } });
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

// 🔹 **Start Server**
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
