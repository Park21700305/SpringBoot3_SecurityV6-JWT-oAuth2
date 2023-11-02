package me.parkjisung;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing // created_at, updated_at을 자동 업데이트
@SpringBootApplication
public class ParkjisungApplication {

	public static void main(String[] args) {
		SpringApplication.run(ParkjisungApplication.class, args);
	}

}
