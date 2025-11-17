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



// ==================== ROUTE: ลงทะเบียนผู้ใช้ ====================
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // ตรวจสอบว่ากรอกข้อมูลครบหรือไม่
    if (!username || !password) {
      return res.status(400).json({ 
        message: 'กรุณากรอก username และ password' 
      });
    }

    // ตรวจสอบว่า username ซ้ำหรือไม่
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(400).json({ 
        message: 'Username นี้ถูกใช้งานแล้ว' 
      });
    }

    // เข้ารหัสรหัสผ่านด้วย bcrypt (saltRounds = 10)
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // สร้างผู้ใช้ใหม่
    const newUser = {
      id: users.length + 1,
      username: username,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // ส่งข้อมูลกลับ (ไม่รวมรหัสผ่าน)
    res.status(201).json({
      message: 'ลงทะเบียนสำเร็จ!',
      user: {
        id: newUser.id,
        username: newUser.username,
        createdAt: newUser.createdAt
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ 
      message: 'เกิดข้อผิดพลาดในการลงทะเบียน' 
    });
  }
});



// ==================== ROUTE: เข้าสู่ระบบ ====================
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // ตรวจสอบว่ากรอกข้อมูลครบหรือไม่
    if (!username || !password) {
      return res.status(400).json({ 
        message: 'กรุณากรอก username และ password' 
      });
    }

    // ค้นหาผู้ใช้จาก username
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ 
        message: 'Username หรือ password ไม่ถูกต้อง' 
      });
    }

    // เปรียบเทียบรหัสผ่านที่กรอกกับรหัสผ่านที่เข้ารหัสไว้
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ 
        message: 'Username หรือ password ไม่ถูกต้อง' 
      });
    }

    // สร้าง Basic Auth token
    // รูปแบบ: username:password -> encode เป็น Base64
    const credentials = `${username}:${password}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');
    const basicAuthToken = `Basic ${encodedCredentials}`;

    // เข้าสู่ระบบสำเร็จ
    res.json({
      message: 'เข้าสู่ระบบสำเร็จ!',
      user: {
        id: user.id,
        username: user.username
      },
      authToken: basicAuthToken,
      instructions: 'นำ authToken ไปใส่ใน Header: "Authorization: <authToken>"'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' 
    });
  }
});


// ==================== MIDDLEWARE: Basic Authentication ====================
const basicAuth = async (req, res, next) => {
  try {
    // ดึง Authorization header
    const authHeader = req.headers.authorization;

    // ตรวจสอบว่ามี header และเป็นรูปแบบ Basic Auth หรือไม่
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      res.setHeader('WWW-Authenticate', 'Basic realm="API Authentication"');
      return res.status(401).json({ 
        message: 'กรุณาระบุ Authorization header',
        format: 'Authorization: Basic <base64-encoded-credentials>'
      });
    }

    // แยกและ decode credentials
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('utf-8');
    const [username, password] = decodedCredentials.split(':');

    // ตรวจสอบว่า decode ได้สำเร็จหรือไม่
    if (!username || !password) {
      return res.status(401).json({ 
        message: 'รูปแบบ credentials ไม่ถูกต้อง' 
      });
    }

    // ค้นหาผู้ใช้
    const user = users.find(u => u.username === username);

    if (!user) {
      res.setHeader('WWW-Authenticate', 'Basic realm="API Authentication"');
      return res.status(401).json({ 
        message: 'ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง' 
      });
    }

    // เปรียบเทียบรหัสผ่าน
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      res.setHeader('WWW-Authenticate', 'Basic realm="API Authentication"');
      return res.status(401).json({ 
        message: 'ข้อมูลการเข้าสู่ระบบไม่ถูกต้อง' 
      });
    }

    // Authentication สำเร็จ - เก็บข้อมูลผู้ใช้ใน request
    req.user = {
      id: user.id,
      username: user.username
    };

    next(); // ไปยัง route ต่อไป

  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(500).json({ 
      message: 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์' 
    });
  }
};


// ==================== ROUTE: ข้อมูลที่ต้องการ Authentication ====================
//=== route have basicAuth ==========
app.get('/api/protected', basicAuth, (req, res) => {
  res.json({
    message: 'คุณเข้าถึงข้อมูลที่ป้องกันสำเร็จ! 🎉',
    user: req.user,
    secretData: {
      level: 'Top Secret',
      content: 'นี่คือข้อมูลที่เฉพาะผู้ใช้ที่ authenticate แล้วเท่านั้นที่เห็นได้',
      timestamp: new Date().toISOString()
    }
  });
});


// ==================== ROUTE: ดูรายชื่อผู้ใช้ทั้งหมด ====================
app.get('/api/users', (req, res) => {
  // ส่งข้อมูลผู้ใช้โดยไม่รวมรหัสผ่าน
  const userList = users.map(user => ({
    id: user.id,
    username: user.username,
    createdAt: user.createdAt
  }));

  res.json({
    message: 'รายชื่อผู้ใช้ทั้งหมด',
    totalUsers: userList.length,
    users: userList
  });
});



// ==================== เริ่มต้น Server ====================
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`🚀 Server กำลังทำงานที่ http://localhost:${PORT}`);
  console.log('='.repeat(50));
  console.log('📌 API Endpoints:');
  console.log(`   GET  / - ดูรายการ endpoints ทั้งหมด`);
  console.log(`   POST /register - ลงทะเบียนผู้ใช้`);
  console.log(`   POST /login - เข้าสู่ระบบ`);
  console.log(`   GET  /api/protected - ข้อมูลที่ต้องการ auth`);
  console.log(`   GET  /api/users - ดูรายชื่อผู้ใช้`);
  console.log('='.repeat(50));
});