const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecret';

const storage = multer.memoryStorage();
const upload = multer({ storage });



const app = express();
const cors = require('cors');
const cookieParser = require('cookie-parser');

app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173', 
  credentials: true               // Allow credentials (cookies, headers)
}));
app.use(cookieParser()); // parse cookies



// Database configuration
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'school_db',
  supportBigNumbers: true,
  bigNumberStrings: true,
  ssl: {
    ca:`-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(conn => {
    console.log('Connected to database successfully!');
    conn.release();
  })
  .catch(err => {
    console.error('Database connection failed:', err);
    process.exit(1);
  });








// REGISTER
app.post('/register', async (req, res) => {
  const {
    email,
    password,
    role,
    first_name = '',
    last_name = '',
    phone = '',
    date_of_birth = null,
    gender = '',
    address = ''
  } = req.body;

  console.log('Registering user:', { email, role, first_name, last_name, phone, date_of_birth });

  // Basic validation
  if (!email || !password || !role) {
    return res.status(400).json({ message: 'Email, password, and role are required' });
  }

  try {
    // 🔍 Check if email already exists
    const [existingRows] = await pool.query('SELECT user_id FROM users WHERE email = ?', [email]);
    if (existingRows.length > 0) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    // 🔐 Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // 📝 Insert new user
    const [result] = await pool.query(`
      INSERT INTO users 
        (email, password_hash, role, first_name, last_name, phone, date_of_birth, gender, address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [email, password_hash, role, first_name, last_name, phone, date_of_birth, gender, address]
    );

    res.status(201).json({
      message: 'User registered',
      user_id: result.insertId
    });

  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
// LOGIN
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
console.log('Login attempt:', { email });
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

const token = jwt.sign(
  { user_id: String(user.user_id), role: user.role },
  JWT_SECRET,
  { expiresIn: '1d' }
)

    console.log('User logged in:', { user_id: user.user_id, role: user.role });

    // Update last_login in database
    await pool.query('UPDATE users SET last_login = NOW() WHERE user_id = ?', [user.user_id]);

    // Set cookies
    res.cookie('auth_token', token, { httpOnly: true, secure: false });
    res.cookie('role', user.role, { httpOnly: true, secure: false });

    res.json({ message: 'Login successful' });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// LOGOUT
app.get('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.clearCookie('role');
  res.json({ message: 'Logged out' });
});

// proile
app.post('/profile/upload', upload.single('image'), async (req, res) => {
  console.log('Profile image upload request:', req.body);
  const userId = req.body.userId; // or from auth middleware
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded' });
  }

  try {
    const user = await getUserById(userId);

    // Delete previous avatar if exists
    if (user.avatar_public_id) {
      await cloudinary.uploader.destroy(user.avatar_public_id);
    }

    // Upload new image
    const stream = cloudinary.uploader.upload_stream(
      { folder: 'user-avatars' },
      async (error, result) => {
        if (error) {
          return res.status(500).json({ success: false, message: error.message });
        }

        // Update DB with new avatar info
        await updateUserAvatar(userId, result.secure_url, result.public_id);

        res.json({
          success: true,
          avatar_url: result.secure_url,
          public_id: result.public_id,
        });
      }
    );

    stream.end(req.file.buffer);
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Delete avatar
app.delete('/profile/delete', async (req, res) => {
  const userId = req.body.userId;

  try {
    const user = await getUserById(userId);

    if (!user.avatar_public_id) {
      return res.status(404).json({ success: false, message: 'No avatar to delete' });
    }

    await cloudinary.uploader.destroy(user.avatar_public_id);
    await updateUserAvatar(userId, null, null);

    res.json({ success: true, message: 'Avatar deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});




// AUTH MIDDLEWARE
function authenticate(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded token user_id type:', typeof decoded.user_id, decoded.user_id);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
}


// ROLE CHECK MIDDLEWARE
function authorize(roles = []) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

// GET CURRENT USER
app.get('/me', authenticate, async (req, res) => {
  try {
    const userIdStr = req.user.user_id;  // Already string

    console.log('Fetching user info for user_id:', userIdStr);

    const [rows] = await pool.query(
      'SELECT user_id, first_name, last_name, email, role, avatar_url FROM users WHERE user_id = ?',
      [userIdStr]
    );

    console.log('User info:', rows);

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error('/me error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});






// PROTECTED ROUTES
app.get('/dashboard', authenticate, (req, res) => {
  res.json({ message: `Hello user ${req.user.user_id}, role: ${req.user.role}` });
});




app.post('/add_assessment', authenticate, authorize(['admin', 'teacher']), async (req, res) => {
  const {
    title,
    type,
    semester,
    year,
    total_marks,
    weight,
    due_date,
    class_id,
  } = req.body.assessment;

  const teacher_id = req.user.user_id;

  console.log('Adding assessment:', {
    title, type, semester, year, total_marks, weight, due_date, class_id
  });

  console.log('Teacher ID:', teacher_id);

  // Validation
  if (!title || !type || !semester || !year || !total_marks || !weight || !due_date || !class_id) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // First, check if teacher exists in teachers table
    const checkTeacherSql = 'SELECT * FROM teachers WHERE teacher_id = ?';
    
    pool.query(checkTeacherSql, [teacher_id], (err, teacherResults) => {
      if (err) {
        console.error('Error checking teacher:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (teacherResults.length === 0) {
        console.error('Teacher not found in teachers table:', teacher_id);
        return res.status(400).json({ 
          error: 'Teacher profile not found. Please complete your teacher profile first.' 
        });
      }

      // Teacher exists, now insert the assessment
      const sql = `
        INSERT INTO assessments (
          class_id, title, type, semester, year,
          total_marks, weight, due_date, teacher_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      const values = [
        class_id,
        title,
        type,
        semester,
        year,
        parseFloat(total_marks),
        parseFloat(weight),
        due_date,
        teacher_id
      ];

      pool.query(sql, values, (err, result) => {
        if (err) {
          console.error('Error inserting assessment:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({
          message: 'Assessment added successfully',
          assessment_id: result.insertId
        });
      });
    });

  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/get_assessments', async (req, res) => {
  const class_id = req.query.class_id;
  const teacher_id = req.query?.teacher_id;

  console.log('Received request:', { class_id, teacher_id });

  if (!class_id || !teacher_id) {
    return res.status(400).json({ 
      success: false,
      message: 'Missing class_id or teacher_id'
    });
  }

  try {
    const class_id_bigint = BigInt(class_id);
    const teacher_id_bigint = BigInt(teacher_id);

    console.log('Query params:', class_id_bigint.toString(), teacher_id_bigint.toString());

    const [rows] = await pool.query(`
      SELECT *
      FROM assessments
      WHERE class_id = ? AND teacher_id = ?
    `, [class_id_bigint.toString(), teacher_id_bigint.toString()]);

    console.log('Query result count:', rows.length);

    res.status(200).json({
      success: true,
      data: rows.map(row => ({
        ...row,
        assessment_id: row.assessment_id?.toString(),
        class_id: row.class_id?.toString(),
        teacher_id: row.teacher_id?.toString()
      }))
    });
  } catch (error) {
    console.error('Error fetching assessments:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      detail: error.message
    });
  }
});

app.get('/get_grades_with_students', async (req, res) => {
  const class_id = req.query.class_id;
  if (!class_id) {
    return res.status(400).json({ success: false, message: 'Missing class_id' });
  }

  try {
    // 1. Get students in the class by matching grade_level and section from classes
    const [students] = await pool.query(`
      SELECT 
        u.user_id AS student_id,
        u.first_name,
        u.last_name,
        s.section,
        s.grade_level
      FROM students s
      JOIN users u ON s.student_id = u.user_id
      JOIN classes c ON s.grade_level = c.grade_level AND s.section = c.section
      WHERE c.class_id = ?
    `, [class_id]);

    // 2. Get all assessments for this class
    const [assessments] = await pool.query(`
      SELECT assessment_id, title, type, total_marks, weight
      FROM assessments
      WHERE class_id = ?
    `, [class_id]);

    // 3. Get all grades for these assessments and students
    const assessmentIds = assessments.map(a => a.assessment_id);
    if (assessmentIds.length === 0) {
      return res.json({ success: true, data: [] });
    }

    const [grades] = await pool.query(`
      SELECT assessment_id, student_id, score
      FROM grades
      WHERE assessment_id IN (?)
    `, [assessmentIds]);

    // 4. Create a map for quick grade lookup
    const gradesMap = {};
    grades.forEach(g => {
      gradesMap[`${g.student_id}_${g.assessment_id}`] = g.score;
    });

    // 5. Construct response
    const result = students.map(student => {
      const studentGrades = assessments.map(assessment => ({
        assessment_id: assessment.assessment_id,
        title: assessment.title,
        type: assessment.type,
        total_marks: assessment.total_marks,
        weight: assessment.weight,
        score: gradesMap[`${student.student_id}_${assessment.assessment_id}`] ?? null,
      }));

      return {
        student_id: student.student_id,
        name: `${student.first_name} ${student.last_name}`,
        section: student.section,
        grade_level: student.grade_level,
        grades: studentGrades,
      };
    });

    res.json({ success: true, data: result });

  } catch (error) {
    console.error('Error fetching student grades:', error);
    res.status(500).json({ success: false, message: 'Internal server error', detail: error.message });
  }
});


app.post('/save_grades', async (req, res) => {
  const { grades } = req.body;
  console.log('Saving grades:', grades);

  if (!grades || !Array.isArray(grades)) {
    return res.status(400).json({ success: false, message: "Invalid request data." });
  }

  try {
    const conn = await pool.getConnection();
    await conn.beginTransaction();

    for (const grade of grades) {
      let { student_id, assessment_id, score } = grade;

      // Ensure IDs are strings or numbers convertible to BigInt safe strings
      if (!student_id || !assessment_id || typeof score !== 'number') {
        await conn.rollback();
        conn.release();
        return res.status(400).json({ success: false, message: "Invalid grade entry." });
      }

      // Convert to string (to safely handle bigint)
      student_id = student_id.toString();
      assessment_id = assessment_id.toString();

      // Check if grade already exists
      const [rows] = await conn.execute(
        `SELECT grade_id FROM grades WHERE student_id = ? AND assessment_id = ?`,
        [student_id, assessment_id]
      );

      if (rows.length > 0) {
        // Update existing grade
        await conn.execute(
          `UPDATE grades SET score = ?, updated_at = CURRENT_TIMESTAMP WHERE student_id = ? AND assessment_id = ?`,
          [score, student_id, assessment_id]
        );
      } else {
        // Insert new grade
        await conn.execute(
          `INSERT INTO grades (student_id, assessment_id, score, created_by) VALUES (?, ?, ?, ?)`,
          [student_id, assessment_id, score, null]  // Set created_by as needed
        );
      }
    }

    await conn.commit();
    conn.release();

    return res.json({ success: true, message: "Grades saved successfully." });

  } catch (error) {
    console.error("Error saving grades:", error);
    return res.status(500).json({ success: false, message: "Server error while saving grades." });
  }
});











app.get('/student', authenticate, authorize(['student']), (req, res) => {
  res.json({ message: 'Student area' });
});

app.get('/teacher-panel', authenticate, authorize(['teacher', 'admin']), (req, res) => {
  res.json({ message: 'Teacher/Admin area' });
});





// 📘 GET students by grade and section
// 📘 GET students by grade and section

app.get('/myclassstudents', async (req, res) => {
console.log('requrstimng being sent ofr stsudnet')

  try {
    const { grade_level, section } = req.query;



    const grade_level_int=parseInt(grade_level)

    console.log(typeof(grade_level_int))

    // 1. Initialize TiDB session
    await pool.query("SET SESSION tidb_enable_streaming = OFF");

    // 2. Execute with explicit casting
  const [rows] = await pool.query(`
  SELECT 
    DISTINCT CAST(u.user_id AS CHAR) as user_id,
    u.first_name,
    u.last_name,
    s.grade_level,
    s.section
  FROM users u FORCE INDEX(PRIMARY)
  INNER JOIN students s FORCE INDEX(PRIMARY) 
    ON BINARY u.user_id = BINARY s.student_id
  WHERE s.grade_level = ?
  AND s.section = ?
  GROUP BY u.user_id
`, [grade_level_int, section]);

    res.json({ success: true, data: rows });
    
  } catch (error) {
    console.error("TiDB Execution Error:", {
      message: error.message,
      sql: error.sql,
      stack: error.stack
    });
    res.status(500).json({ 
      success: false,
      error: "Query execution failed" 
    });
  }
});
//  save attendace to the database

app.post('/api/save-attendance', async (req, res) => {
  const { teacher_id, classId, date, attendance } = req.body;

  console.log("Received attendance data:", req.body);

  if (!teacher_id || !classId || !date || !attendance?.length) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  // Check if attendance already exists for this class/date
  try {
    const checkQuery = `
      SELECT COUNT(*) as count 
      FROM attendance 
      WHERE class_id = ? AND date = ?
    `;
    
    const [results] = await pool.query(checkQuery, [classId, date]);
    const attendanceExists = results[0].count > 0;

    if (attendanceExists) {
      return res.status(409).json({ 
        success: false, 
        message: "Attendance already recorded for this class and date" 
      });
    }

    // If no existing attendance, proceed with insertion
    const insertQuery = `
      INSERT INTO attendance 
        (student_id, class_id, date, status, recorded_by, notes)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    // Use transaction for atomic operations
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      for (const record of attendance) {
        const { student_id, status, notes } = record;
        await connection.query(insertQuery, [
          student_id,
          classId,
          date,
          status,
          teacher_id,
          notes || null
        ]);
      }

      await connection.commit();
      res.status(200).json({ success: true, message: "Attendance recorded." });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }

  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Server error while recording attendance.",
      error: error.message 
    });
  }
});

//  get attendance for a class on a specific date

app.get('/api/class-attendance', async (req, res) => {
  const { class_id, date } = req.query;

  if (!class_id || !date) {
    return res.status(400).json({
      success: false,
      message: "Both class_id and date are required"
    });
  }

  try {
    // Convert to proper types
    const class_id_bigint = BigInt(class_id); // Handle 64-bit integers
    const formattedDate = new Date(date).toISOString().split('T')[0];

    console.log('Query params:', {
      class_id: class_id_bigint.toString(),
      date: formattedDate
    });

    const [rows] = await pool.query(`
      SELECT DISTINCT 
        a.student_id,
        u.first_name,
        u.last_name,
        a.status,
        a.notes
      FROM attendance a FORCE INDEX(idx_date_class)
      LEFT JOIN users u ON u.user_id = a.student_id
      WHERE a.class_id = ?
        AND a.date = ?
    `, [class_id_bigint.toString(), formattedDate]);

    console.log('Query results:', rows);
    
    res.status(200).json({
      success: true,
      data: rows.map(row => ({
        ...row,
        student_id: row.student_id.toString() // Convert bigint to string
      }))
    });
  } catch (error) {
    console.error("Error fetching attendance:", {
      error: error.message,
      stack: error.stack,
      queryParams: { class_id, date }
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
      detail: error.message
    });
  }
});



// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));