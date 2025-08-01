package com.mohaedbashir.ecommerce.repository;

import com.mohaedbashir.ecommerce.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
