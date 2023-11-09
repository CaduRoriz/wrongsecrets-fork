package org.owasp.wrongsecrets.challenges.docker;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.owasp.wrongsecrets.RuntimeEnvironment;
import org.owasp.wrongsecrets.ScoreCard;
import org.owasp.wrongsecrets.challenges.Challenge;
import org.owasp.wrongsecrets.challenges.ChallengeTechnology;
import org.owasp.wrongsecrets.challenges.Difficulty;
import org.owasp.wrongsecrets.challenges.Spoiler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Order(42) // Ajuste a ordem conforme necessário
public class Challenge44 extends Challenge {

  private final String salt;
  private final String answerHash;

  public Challenge42(
      ScoreCard scoreCard,
      @Value("${challenge42saltA}") String salt,
      @Value("${challenge42Answer}") String answer) {
    super(scoreCard);
    this.salt = salt;
    this.answerHash = encryptWithMD5(answer, salt);
  }

  @Override
  public boolean canRunInCTFMode() {
    return true;
  }

  @Override
  public Spoiler spoiler() {
    return new Spoiler("The secret message was encrypted using an MD5 hash function. To describe you will need to find the original number
    and derive the MD5 keu correctly. Check the MD5 documentation and consider how you can generate an MD5 hash from number between 0 and 99999"); 
  }

  @Override
  public int difficulty() {
    return Difficulty.HARD;
  }

  @Override
  public String getTech() {
    return ChallengeTechnology.Tech.CRYPTOGRAPHY.id;
  }

  @Override
  public boolean isLimitedWhenOnlineHosted() {
    return false;
  }

  @Override
  public List<RuntimeEnvironment.Environment> supportedRuntimeEnvironments() {
    return List.of(RuntimeEnvironment.Environment.DOCKER);
  }

  @Override
  public boolean answerCorrect(String userAnswer) {
   
    String userAnswerHash = encryptWithMD5(userAnswer, salt);
    return userAnswerHash.equals(answerHash);
  }

  private String encryptWithMD5(String text, String salt) {
    
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      String saltedText = text + salt;
      byte[] result = md.digest(saltedText.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(result);
    } catch (NoSuchAlgorithmException e) {
      log.error("error in md5 key derivation", e);
      return "";
    }
  }
}
