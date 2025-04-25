# 🔐 JWT Auth Demo

A Spring Boot application demonstrating JWT (JSON Web Token) based authentication.

## 🧰 Technologies Used

- Java 21
- Spring Boot 3
- Spring Security 6
- JWT (io.jsonwebtoken)
- Spring Data JPA
- MySQL
- Lombok
- Maven

## 🚀 Getting Started

1. Open the file `src/main/resources/application.yml` and configure your local environment:

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/your_db
spring.datasource.username=your_username
spring.datasource.password=your_password
jwt.secret=your_jwt_secret_key
