import { Post, IPost } from '../models/Post';

export class PostService {
  static async createPost(postData: Partial<IPost>): Promise<IPost> {
    const post = await Post.create(postData);
    return post.populate('author', 'username email');
  }

  static async getAllPosts(page = 1, limit = 10, published?: boolean): Promise<{ posts: IPost[]; total: number }> {
    const skip = (page - 1) * limit;
    const filter = published !== undefined ? { isPublished: published } : {};
    
    const [posts, total] = await Promise.all([
      Post.find(filter)
        .populate('author', 'username email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Post.countDocuments(filter)
    ]);

    return { posts, total };
  }

  static async getPostById(id: string): Promise<IPost> {
    const post = await Post.findById(id).populate('author', 'username email');
    if (!post) {
      throw new Error('Post not found');
    }
    return post;
  }

  static async updatePost(id: string, updateData: Partial<IPost>, userId: string): Promise<IPost> {
    const post = await Post.findOneAndUpdate(
      { _id: id, author: userId },
      updateData,
      { new: true }
    ).populate('author', 'username email');
    
    if (!post) {
      throw new Error('Post not found or unauthorized');
    }
    return post;
  }

  static async deletePost(id: string, userId: string): Promise<void> {
    const result = await Post.findOneAndDelete({ _id: id, author: userId });
    if (!result) {
      throw new Error('Post not found or unauthorized');
    }
  }
}