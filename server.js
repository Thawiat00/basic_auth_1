const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// Middleware สำหรับ parse JSON
app.use(express.json());