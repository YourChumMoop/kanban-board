import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  
  const { username, password } = req.body; //get the username and password from the login request

  const user = await User.findOne({ //search for the user
    where: { username },
  });
  if (!user) { //if no user is found, you cant login!
    return res.status(401).json({ message: 'Authentication failed' });
  }

  const passwordIsValid = await bcrypt.compare(password, user.password); //compare the password given with the encryted one
  if (!passwordIsValid) { //if they don't match, auth fails
    return res.status(401).json({ message: 'Authentication failed' });
  }

  const secretKey = process.env.JWT_SECRET_KEY || '';

  const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' }); //if they do, sign a JWT token and pass it on
  return res.json({ token });
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
