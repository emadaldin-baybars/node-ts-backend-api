import { User, IUser } from '../models/User';

export class UserService {
  static async getAllUsers(page = 1, limit = 10): Promise<{ users: IUser[]; total: number }> {
    const skip = (page - 1) * limit;
    
    const [users, total] = await Promise.all([
      User.find({ isActive: true }).skip(skip).limit(limit),
      User.countDocuments({ isActive: true })
    ]);

    return { users, total };
  }

  static async getUserById(id: string): Promise<IUser> {
    const user = await User.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  static async updateUser(id: string, updateData: Partial<IUser>): Promise<IUser> {
    const user = await User.findByIdAndUpdate(id, updateData, { new: true });
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  static async deleteUser(id: string): Promise<void> {
    const user = await User.findByIdAndUpdate(id, { isActive: false });
    if (!user) {
      throw new Error('User not found');
    }
  }
}