import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDTO, RegisterUserDTO } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService');

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('Connected to the database MongoDB');
    }

    async registerUser(registerUserDto: RegisterUserDTO) {
        const { email, name, password } = registerUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email,
                },
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists',
                });
            }

            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password: bcrypt.hashSync(password, 10),
                },
            });

            const { password: __, ...rest } = newUser;

            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDTO) {
        const { email, password } = loginUserDto;
        try {
            const user = await this.user.findUnique({
                where: {
                    email,
                },
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'User not exists',
                });
            }

            const isPasswordMatch = bcrypt.compareSync(password, user.password);

            if (!isPasswordMatch) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid password',
                });
            }

            const { password: __, ...rest } = user;

            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            });
        }
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string) {
        try {
            const { sub, iat, exp, ...rest } = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });

            return {
                user: rest,
                token: await this.signJWT(rest),
            }
        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid token',
            });
        }
    }
}
