Bcrypt for Delphi
==================

[Bcrypt](http://en.wikipedia.org/wiki/Bcrypt) is an algorithm designed for hashing passwords, and only passwords; i.e., it's:

- not a high-speed, generic hashing algorithm;
- computationally and memory expensive;
- limited to passwords of 55 bytes.

It was first [described by Niels Provos and David Mazières in 1999](http://static.usenix.org/events/usenix99/provos/provos.pdf) for OpenBSD.

It uses the Blowfish encryption algorithm, but with an "expensive key setup" modification, contained in the function `EksBlowfishSetup`.

Sample Usage
----------------

- To hash a password:

        hash := TBCrypt.HashPassword('correct battery horse staple'); //using default cost factor
    
- To hash a password specifying your own cost factor:

        hash := TBCrypt.HashPassword('correct battery horse staple', 14); //specify cost factor 14
    
- To verify a password:

        isPasswordValid := TBCrypt.CheckPassword('correct battery horse stapler', expectedHash);


    
By convention BCrypt outputs a hash as string such as:

    $2a$10$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm

The parts of the string are:

| Value | Meaning | Notes |
|-------|---------|-------|
| 2a | Hash algorithm | "2a" = current version of BCrypt, "2" = obsolete version of BCrypt, "1" = MD5 |
| 10 | cost factor | Will iterate for 2^10=1024 rounds. (Default is 10) |
| Ro0CUfOqk6cXEKf3dyaM7O | Salt | 22 base64 encoded characters |
| hSCvnwM9s4wIX9JeLapehKK5YdLxKcm | Hashed password | 31 base64 encoded characters |

Because the **cost factor** is stored with the hash output, bcrypt hashes are backwards and forwards compatible with
	changing the number of rounds. It also makes BCrypt extraordinarily convenient; a random salt is automatically generated and stored for you.

Speed Tests
--------------

The current (1/1/2015) hard-coded default for cost is **10**. This results in 2^10 = 1,024 rounds during the key setup.

Intel Core i7-2700K CPU @ 3.50 GHz (1/23/2014, Delphi 5):

| Cost | Iterations        |    Duration | Notes |
|------|-------------------|-------------|-------|
|  8   |    256 iterations |     59.8 ms | minimum allowed by BCrypt |
|  9   |    512 iterations |    114.6 ms |
| 10   |  1,024 iterations |    234.8 ms | current default (`BCRYPT_COST=10`) |
| 11   |  2,048 iterations |    463.6 ms |
| 12   |  4,096 iterations |    924.3 ms |
| 13   |  8,192 iterations |  1,843.8 ms |
| 14   | 16,384 iterations |  3,693.2 ms |
| 15   | 32,768 iterations |  7,364.7 ms |
| 16   | 65,536 iterations | 14,602.8 ms |

At the time of publication (1999), the default cost was **6** for a normal user and **8** for the superuser. 

Created by [Ian Boyd 5/3/2012](http://stackoverflow.com/a/10441765/9990)

Public Domain
