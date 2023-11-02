package me.parkjisung.springbootdeveloper.repository;

import me.parkjisung.springbootdeveloper.domain.Article;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlogRepository extends JpaRepository<Article, Long> {
}
