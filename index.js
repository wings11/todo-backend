require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// PostgreSQL connection (Supabase) using DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Validate token endpoint
app.get('/api/validate-token', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT username FROM users WHERE id = $1', [req.user.id]);
    if (result.rows[0]) {
      res.json({ username: result.rows[0].username });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User endpoint for dropdown (filtered by team_id if provided)
app.get('/api/users', authenticateToken, async (req, res) => {
  const { team_id } = req.query;
  try {
    let query = 'SELECT id, username FROM users WHERE id IN (SELECT user_id FROM user_team WHERE team_id IN (SELECT team_id FROM user_team WHERE user_id = $1))';
    const params = [req.user.id];
    if (team_id) {
      query = 'SELECT id, username FROM users WHERE id IN (SELECT user_id FROM user_team WHERE team_id = $1)';
      params[0] = team_id;
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Team endpoint for dropdown
app.get('/api/teams', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM teams WHERE id IN (SELECT team_id FROM user_team WHERE user_id = $1)', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Task endpoints
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT t.*, u.username AS assigned_user, r.name AS assigned_role ' +
      'FROM tasks t ' +
      'LEFT JOIN users u ON t.assigned_to = u.id ' +
      'LEFT JOIN roles r ON u.role_id = r.id ' +
      'WHERE t.team_id IN (SELECT team_id FROM user_team WHERE user_id = $1)',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { title, description, due_date, status, assigned_to, team_id } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO tasks (title, description, due_date, status, assigned_to, team_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, description, due_date, status, assigned_to, team_id]
    );
    const newTask = result.rows[0];
    const assignedUser = await pool.query('SELECT username FROM users WHERE id = $1', [assigned_to]);
    const assignedRole = await pool.query('SELECT r.name FROM roles r JOIN users u ON u.role_id = r.id WHERE u.id = $1', [assigned_to]);
    const notification = await pool.query(
      'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
      [assigned_to, `New task assigned: ${title}`]
    );
    io.emit('taskUpdate', {
      ...newTask,
      assigned_user: assignedUser.rows[0]?.username,
      assigned_role: assignedRole.rows[0]?.name,
    });
    io.emit('notification', notification.rows[0]);
    res.json({
      ...newTask,
      assigned_user: assignedUser.rows[0]?.username,
      assigned_role: assignedRole.rows[0]?.name,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, due_date, status, assigned_to } = req.body;
  try {
    const result = await pool.query(
      'UPDATE tasks SET title = $1, description = $2, due_date = $3, status = $4, assigned_to = $5 WHERE id = $6 RETURNING *',
      [title, description, due_date, status, assigned_to, id]
    );
    const updatedTask = result.rows[0];
    const assignedUser = await pool.query('SELECT username FROM users WHERE id = $1', [assigned_to]);
    const assignedRole = await pool.query('SELECT r.name FROM roles r JOIN users u ON u.role_id = r.id WHERE u.id = $1', [assigned_to]);
    const notification = await pool.query(
      'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
      [assigned_to, `Task updated: ${title}`]
    );
    io.emit('taskUpdate', {
      ...updatedTask,
      assigned_user: assignedUser.rows[0]?.username,
      assigned_role: assignedRole.rows[0]?.name,
    });
    io.emit('notification', notification.rows[0]);
    res.json({
      ...updatedTask,
      assigned_user: assignedUser.rows[0]?.username,
      assigned_role: assignedRole.rows[0]?.name,
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM tasks WHERE id = $1 RETURNING *', [id]);
    const deletedTask = result.rows[0];
    const notification = await pool.query(
      'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
      [req.user.id, `Task deleted: ${deletedTask.title}`]
    );
    io.emit('taskUpdate', { id, deleted: true });
    io.emit('notification', notification.rows[0]);
    res.json({ message: 'Task deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Comment endpoints
app.get('/api/comments', authenticateToken, async (req, res) => {
  const { task_id } = req.query;
  try {
    const result = await pool.query(
      'SELECT c.*, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.task_id = $1',
      [task_id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/comments', authenticateToken, async (req, res) => {
  const { task_id, content } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO comments (task_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
      [task_id, req.user.id, content]
    );
    const newComment = {
      ...result.rows[0],
      username: req.user.username,
    };
    io.emit('newComment', newComment);
    res.json(newComment);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Socket.IO for real-time
io.on('connection', (socket) => {
  socket.on('comment', async (data) => {
    const { task_id, content, user_id } = data;
    try {
      const result = await pool.query(
        'INSERT INTO comments (task_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
        [task_id, user_id, content]
      );
      const newComment = {
        ...result.rows[0],
        username: (await pool.query('SELECT username FROM users WHERE id = $1', [user_id])).rows[0].username,
      };
      io.emit('newComment', newComment);
    } catch (err) {
      console.error(err);
    }
  });
});
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));