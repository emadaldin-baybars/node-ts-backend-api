import { User, IUser } from '../models/User';
import { generateToken } from '../utils/jwt';
import { LoginCredentials, RegisterCredentials } from '../types/auth';

export class AuthService {
  static async register(userData: RegisterCredentials): Promise<{ user: IUser; token: string }> {
    const existingUser = await User.findOne({
      $or: [{ email: userData.email }, { username: userData.username }]
    });

    if (existingUser) {
      throw new Error('User already exists with this email or username');
    }

    const user = await User.create(userData);
    const token = generateToken({ userId: (user._id as any).toString(), role: user.role });

    return { user, token };
  }

  static async login(credentials: LoginCredentials): Promise<{ user: IUser; token: string }> {
    const user = await User.findOne({ email: credentials.email }).select('+password');

    if (!user || !(await user.comparePassword(credentials.password))) {
      throw new Error('Invalid email or password');
    }

    if (!user.isActive) {
      throw new Error('Account is deactivated');
    }

    const token = generateToken({ userId: (user._id as any).toString(), role: user.role });

    return { user, token };
  }

  static async getProfile(userId: string): Promise<IUser> {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }
}