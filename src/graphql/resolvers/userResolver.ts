import { AuthService } from '../../services/authService';
import { UserService } from '../../services/userService';
import { AuthenticationError } from 'apollo-server-express';

export const userResolvers = {
  Query: {
    me: async (_: any, __: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return user;
    },

    users: async (_: any, { page = 1, limit = 10 }: any, { user }: any) => {
      if (!user || user.role !== 'admin') {
        throw new AuthenticationError('Admin access required');
      }
      return await UserService.getAllUsers(page, limit);
    },
  },

  Mutation: {
    register: async (_: any, { input }: any) => {
      return await AuthService.register(input);
    },

    login: async (_: any, { input }: any) => {
      return await AuthService.login(input);
    },
  },
};
