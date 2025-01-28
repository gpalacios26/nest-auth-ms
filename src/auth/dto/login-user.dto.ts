import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class LoginUserDTO {

    @IsString()
    @IsEmail()
    email: string;

    @IsString()
    @IsStrongPassword()
    password: string;
}