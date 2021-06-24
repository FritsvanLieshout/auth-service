package com.kwetter.frits.authservice.logic.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kwetter.frits.authservice.configuration.KafkaProperties;
import com.kwetter.frits.authservice.logic.dto.UserDTO;
import com.kwetter.frits.authservice.repository.UserRepository;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.WakeupException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class UserEditConsumer {

    private final Logger log = LoggerFactory.getLogger(UserEditConsumer.class);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final KafkaProperties kafkaProperties;

    public static final String TOPIC = "user-edited";

    private KafkaConsumer<String, String> kafkaConsumer;
    private UserRepository userRepository;
    private ExecutorService executorService = Executors.newCachedThreadPool();

    public UserEditConsumer(KafkaProperties kafkaProperties, UserRepository userRepository) {
        this.kafkaProperties = kafkaProperties;
        this.userRepository = userRepository;
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

                        var objectMapper = new ObjectMapper();
                        var userDTO = objectMapper.readValue(record.value(), UserDTO.class);
                        var user = userRepository.findUserByUsername(userDTO.getUsername());
                        if (user != null && !user.getRole().equals(userDTO.getRole())) {
                            user.setRole(userDTO.getRole());
                            userRepository.save(user);
                        }
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
