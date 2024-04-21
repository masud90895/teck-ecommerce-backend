import bcrypt from 'bcrypt';
import httpStatus from 'http-status';
import { Secret } from 'jsonwebtoken';

import config from '../../../config';
import ApiError from '../../../errors/ApiError';
import { jwtHelpers } from '../../../helpers/jwtHelpers';

import { User } from '@prisma/client';
import prisma from '../../../shared/prisma';
import { ISingUpUserResponse } from './user.interface';

const registerUser = async (user: User): Promise<ISingUpUserResponse> => {
  const isUserExist = await prisma.user.findUnique({
    where: { email: user.email },
  });

  if (isUserExist) {
    throw new ApiError(httpStatus.CONFLICT, 'User already exist');
  }

  user.password = await bcrypt.hash(
    user.password,
    Number(config.bycrypt_salt_rounds),
  );

  const newUser = await prisma.user.create({ data: user });

  const { id: userId, role, name, email } = newUser;

  const accessToken = jwtHelpers.createToken(
    { userId, role, name, email },
    config.jwt.secret as Secret,
    config.jwt.expires_in as string,
  );

  const refreshToken = jwtHelpers.createToken(
    { userId, role },
    config.jwt.refresh_secret as Secret,
    config.jwt.refresh_expires_in as string,
  );

  return {
    newUser,
    accessToken,
    refreshToken,
  };
};

const loginUser = async (payload: { email: string; password: string }) => {
  const { email, password } = payload;

  const isPasswordMatched = async (
    givenPassword: string,
    savedPassword: string,
  ) => {
    return await bcrypt.compare(givenPassword, savedPassword);
  };

  const isUserExist = await prisma.user.findUnique({ where: { email } });

  if (!isUserExist) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User does not exist');
  }

  if (
    isUserExist.password &&
    !(await isPasswordMatched(password, isUserExist.password))
  ) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password is incorrect');
  }

  //create access token & refresh token

  const { id: userId, role, name } = isUserExist;
  const accessToken = jwtHelpers.createToken(
    { userId, role, name, email },
    config.jwt.secret as Secret,
    config.jwt.expires_in as string,
  );
  const refreshToken = jwtHelpers.createToken(
    { userId, role },
    config.jwt.refresh_secret as Secret,
    config.jwt.refresh_expires_in as string,
  );

  return { accessToken, refreshToken };
};

const getProfile = async (userId: string): Promise<User | null> => {
  const result = await prisma.user.findUnique({ where: { id: userId } });
  return result;
};

export const UserService = {
  registerUser,
  loginUser,
  getProfile,
};
