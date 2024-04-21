import express from 'express';
  
import { ENUM_USER_ROLE } from '../../../enums/user';
import auth from '../../middlewares/auth';
import { UserController } from './user.controller';

const router = express.Router();

router.get(
  '/profile',
  auth(ENUM_USER_ROLE.ADMIN, ENUM_USER_ROLE.USER),
  UserController.getProfile
);
router.post('/signup', UserController.registerUser);
router.post('/login', UserController.loginUser);

export const AuthRouter = router;
