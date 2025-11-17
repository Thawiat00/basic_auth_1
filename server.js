const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

// Middleware สำหรับ parse JSON
app.use(express.json());


// ฐานข้อมูลผู้ใช้ในหน่วยความจำ (สำหรับการทดสอบ)
// ในการใช้งานจริง ควรใช้ฐานข้อมูลจริง เช่น MongoDB, PostgreSQL
const users = [];


// ==================== ROUTE: หน้าแรก ====================
app.get('/', (req, res) => {
  res.json({
    message: 'ยินดีต้อนรับสู่ Basic Auth API',
    endpoints: {
      register: 'POST /register - ลงทะเบียนผู้ใช้ใหม่',
      login: 'POST /login - เข้าสู่ระบบ',
      protected: 'GET /api/protected - ข้อมูลที่ต้องการ authentication',
      users: 'GET /api/users - ดูรายชื่อผู้ใช้ทั้งหมด (ไม่มีรหัสผ่าน)'
    }
  });
});