package com.kwetter.frits.authservice.logic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kwetter.frits.authservice.configuration.KafkaProperties;
import com.kwetter.frits.authservice.entity.User;
import com.kwetter.frits.authservice.logic.dto.UserAuthDTO;
import com.kwetter.frits.authservice.repository.UserRepository;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.WakeupException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.kwetter.frits.authservice.entity.UserRole.*;

@Service
public class UserConsumer {

    private final Logger log = LoggerFactory.getLogger(UserConsumer.class);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final KafkaProperties kafkaProperties;

    public static final String TOPIC = "user-register";

    private KafkaConsumer<String, String> kafkaConsumer;
    private final UserRepository userRepository;
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final PasswordEncoder passwordEncoder;

    public UserConsumer(KafkaProperties kafkaProperties, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.kafkaProperties = kafkaProperties;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void start() {

        log.info("Kafka consumer starting...");
        this.kafkaConsumer = new KafkaConsumer<>(kafkaProperties.getConsumerProps());
        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown));
        kafkaConsumer.subscribe(Collections.singletonList(TOPIC));
        log.info("Kafka consumer started");

        executorService.execute(() -> {
            try {
                while (!closed.get()) {
                    ConsumerRecords<String, String> records = kafkaConsumer.poll(Duration.ofSeconds(3));
                    for (ConsumerRecord<String, String> record : records) {
                        log.info("Consumed message in {} : {}", TOPIC, record.value());

                        ObjectMapper objectMapper = new ObjectMapper();
                        UserAuthDTO userAuthDTO = objectMapper.readValue(record.value(), UserAuthDTO.class);
                        User user = new User(userAuthDTO.getUserId(), userAuthDTO.getUsername(), passwordEncoder.encode(userAuthDTO.getPassword()), KWETTER_USER.name());
                        userRepository.save(user);
                    }
                }
                kafkaConsumer.commitSync();
            } catch (WakeupException e) {
                if (!closed.get()) throw e;
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            } finally {
                log.info("Kafka consumer close");
                kafkaConsumer.close();
            }
        });
    }

    public KafkaConsumer<String, String> getKafkaConsumer() {
        return kafkaConsumer;
    }

    public void shutdown() {
        log.info("Shutdown Kafka consumer");
        closed.set(true);
        kafkaConsumer.wakeup();
    }
}
