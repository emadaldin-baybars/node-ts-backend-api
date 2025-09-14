import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authenticate, authorize } from '../middleware/auth';

const router = Router();

router.get('/', authenticate, authorize('admin'), UserController.getAllUsers);
router.get('/:id', authenticate, UserController.getUserById);
router.put('/:id', authenticate, UserController.updateUser);
router.delete('/:id', authenticate, authorize('admin'), UserController.deleteUser);

export default router;