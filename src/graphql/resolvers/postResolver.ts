import { PostService } from '../../services/postService';
import { AuthenticationError } from 'apollo-server-express';

export const postResolvers = {
  Query: {
    posts: async (_: any, { page = 1, limit = 10, published }: any) => {
      return await PostService.getAllPosts(page, limit, published);
    },

    post: async (_: any, { id }: any) => {
      return await PostService.getPostById(id);
    },
  },

  Mutation: {
    createPost: async (_: any, { input }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return await PostService.createPost({ ...input, author: user._id });
    },

    updatePost: async (_: any, { id, input }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      return await PostService.updatePost(id, input, user._id);
    },

    deletePost: async (_: any, { id }: any, { user }: any) => {
      if (!user) {
        throw new AuthenticationError('Not authenticated');
      }
      await PostService.deletePost(id, user._id);
      return true;
    },
  },
};
