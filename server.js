const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// Middleware สำหรับ parse JSON
app.use(express.json());


// ฐานข้อมูลผู้ใช้ในหน่วยความจำ (สำหรับการทดสอบ)
// ในการใช้งานจริง ควรใช้ฐานข้อมูลจริง เช่น MongoDB, PostgreSQL
const users = [];