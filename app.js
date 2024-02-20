const express = require('express');
const cors = require('cors');

const bcrypt = require('bcrypt');
const app = express();
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const connection = require('./db');

app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    connection.query(
      'SELECT id, username, email, password, role FROM karyawan WHERE email = ?',
      [email],
      (error, results) => {
        if (error) {
          console.error(error);
          return res.status(500).json({ success: false, error: 'Internal server error' });
        }
  
        if (results.length > 0) {
          const user = results[0];
  
          bcrypt.compare(password, user.password, (bcryptError, isPasswordValid) => {
            if (bcryptError) {
              console.error(bcryptError);
              return res.status(500).json({ success: false, error: 'Internal server error' });
            }
  
            if (isPasswordValid) {
              return res.json({
                success: true,
                message: 'Login successful!',
                data: {
                  id: user.id,
                  username: user.username,
                  email: user.email,
                  role: user.role,
                },
              });
            } else {
              return res.status(401).json({
                success: false,
                error: 'Invalid email or password',
              });
            }
          });
        } else {
          return res.status(401).json({
            success: false,
            error: 'User Not Found',
          });
        }
      }
    );
});

app.post('/loginUser', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      const sql = 'SELECT * FROM karyawan WHERE email = ?';
      connection.query(sql, [email], async (err, result) => {
        if (err) {
          console.error('Error during login:', err);
          res.status(500).json({ error: 'Internal Server Error' });
        } else {
          const karyawan = result[0];
  
          if (!karyawan) {
            return res.status(401).json({ error: 'Invalid email or password' });
          }

          const match = await bcrypt.compare(password, karyawan.password);
  
          if (!match) {
            return res.status(401).json({ error: 'Invalid email or password' });
          }

          const token = jwt.sign({ email: karyawan.email }, 'secretKey', { expiresIn: '1h' });
  
          res.json({ token });
        }
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/getData', (req, res) => {
    connection.query('SELECT * FROM karyawan', (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/getData/:id', (req, res) => {
    const id = req.params.id;
    
    connection.query('SELECT * FROM karyawan WHERE id = ?', [id], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ message: 'Data not found' });
        }
    });
});

app.post('/insertData', (req, res) => {
    const { username, email, password, nama_lengkap, jenis_kelamin, role } = req.body; 
    const newData = { username, email, password, nama_lengkap, jenis_kelamin, role };
    connection.query('INSERT INTO karyawan SET ?', newData, (err, results) => {
        try {
          if (err) throw err;
          res.json({ message: 'New data has been inserted', id: results.insertId });
        } catch (error) {
          res.json({ message: 'Eror', error });
        }
    });
});

app.put('/updateData/:id', (req, res) => {
    const id = req.params.id;
    const { username, email, password, nama_lengkap, jenis_kelamin, role } = req.body;
    
    connection.query(
        "UPDATE karyawan SET username = ?, email = ?, password = ?, nama_lengkap = ?, jenis_kelamin = ?, role = ? WHERE id = ?", 
        [username, email, password, nama_lengkap, jenis_kelamin, role, id], 
        (error, results) => {
            if (error) throw error;
            res.json({ 
                message: 'Data has been updated', 
                affectedRows: results.affectedRows,
            });
        }
    );
});

app.delete('/deleteData/:id', (req, res) => {
    const id = req.params.id;

    connection.query('DELETE FROM karyawan WHERE id = ?', [id], (err, results) => {
        if (err) throw err;
        res.json({ 
            message: 'Data has been deleted', 
            affectedRows: results.affectedRows,
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
