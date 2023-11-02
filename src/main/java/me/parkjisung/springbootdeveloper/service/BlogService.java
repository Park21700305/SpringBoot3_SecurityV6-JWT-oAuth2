package me.parkjisung.springbootdeveloper.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import me.parkjisung.springbootdeveloper.domain.Article;
import me.parkjisung.springbootdeveloper.dto.AddArticleRequest;
import me.parkjisung.springbootdeveloper.dto.UpdateArticleRequest;
import org.springframework.stereotype.Service;
import me.parkjisung.springbootdeveloper.repository.BlogRepository;

import java.util.List;

@RequiredArgsConstructor // final이 붙거나 @NonNull이 붙은 필드의 생성자 추가
@Service
public class BlogService {

    private final BlogRepository blogRepository;

    // 블로그 글 추가 메서드
    public Article save(AddArticleRequest request) {
        return blogRepository.save(request.toEntity());
    }

    public List<Article> findAll() {
        return blogRepository.findAll();
    }

    public Article findById(Long id) {
        return blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not found: " + id));
    }

    public void delete(Long id) {
        blogRepository.deleteById(id);
    }

    @Transactional
    public Article update(Long id, UpdateArticleRequest request) {
        Article article = blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not found: " + id));
        article.update(request.getTitle(), request.getContent());

        return article;
    }
}
