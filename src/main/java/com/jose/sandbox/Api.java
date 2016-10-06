package com.jose.sandbox;

import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.jose.sandbox.event.EmailFormattedMessage;
import com.jose.sandbox.event.EmailNotification;
import com.jose.sandbox.contexts.EscalateToAdminsContext;
import com.jose.sandbox.contexts.FeedbackContext;
import com.jose.sandbox.model.GetUserFromToken;
import com.jose.sandbox.model.JwtBearerAuthorizationPattern;
import com.jose.sandbox.model.JwtSubjectContent;
import com.jose.sandbox.contexts.LoggedOutResetPasswordContext;
import com.jose.sandbox.model.LoginResponse;
import com.jose.sandbox.contexts.NewUserRegistrationContext;
import com.jose.sandbox.model.ParseUserJwtToken;
import com.jose.sandbox.model.Queue;
import com.jose.sandbox.model.QueueDeserializer;
import com.jose.sandbox.model.SimpleResponse;
import com.jose.sandbox.model.TokenVerification;
import com.jose.sandbox.contexts.TokenVerificationContext;
import com.jose.sandbox.contexts.UpdateUserContext;
import com.jose.sandbox.model.User;
import com.jose.sandbox.model.UserEscalation;
import com.jose.sandbox.model.UserFeedback;
import com.jose.sandbox.contexts.UserLoginContext;
import com.jose.sandbox.model.UserLogins;
import com.jose.sandbox.contexts.UserLogoutContext;
import com.jose.sandbox.model.UserType;
import com.jose.sandbox.model.UserTypeAssociation;
import com.jose.sandbox.repository.DrawRepository;
import com.jose.sandbox.repository.GameRepository;
import com.jose.sandbox.repository.QueueRepository;
import com.jose.sandbox.repository.TokenVerificationRepository;
import com.jose.sandbox.repository.UserEscalationRepository;
import com.jose.sandbox.repository.UserFeedbackRepository;
import com.jose.sandbox.repository.UserLoginsRepository;
import com.jose.sandbox.repository.UserRepository;
import com.jose.sandbox.repository.UserTypeAssociationRepository;
import com.jose.sandbox.repository.UserTypeRepository;
import com.jose.sandbox.services.BCrypt;
import com.jose.sandbox.services.RandomString;
import com.jose.sandbox.utils.DateUtils;
import com.jose.sandbox.validators.GameNameProvided;
import com.jose.sandbox.validators.MultiplierProvidedValidation;
import com.jose.sandbox.validators.NumbersProvidedValidation;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import net.dongliu.gson.GsonJava8TypeAdapterFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static spark.Spark.before;
import static spark.Spark.delete;
import static spark.Spark.get;
import static spark.Spark.halt;
import static spark.Spark.post;
import static spark.Spark.put;

//import com.jcabi.aspects.Loggable;

/**
 * The REST API
 * Created by jose on 11/4/15.
 */
@Component
//@Loggable
public class Api {
    private static final Logger log = LoggerFactory.getLogger(Api.class);
    private static final int PASSWORD_LENGTH = 10;
    private static final String BLANK = "";
    private static final String PENDING_VERIFICATION = "pending_verification";
    private static final String TERMINATED = "terminated";
    private static final String CLOSED = "closed";
    private static final String RESET_PASSWORD_FLAG = "reset_password";
    private static final String PENDING = "pending";
    private static final int EMAIL_VERIFICATION_EXPIRY_3_DAYS = 3;
    private static final int LOGIN_EXPIRY_JWT_1_DAY = 1;
    private static final String VERIFIED = "verified";
    private static final String NORMAL_USER = "user";
    private static final String EMAIL_TYPE = "email";
    private static final String ACTIVE = "active";
    private static final String JWT_BEARER_AUTHORIZATION = new JwtBearerAuthorizationPattern().pattern();
//    private static final String PUBLIC_ENDPOINT_PATTERN = "^/public/";
    private static final String PRIVATE_ENDPOINT_PATTERN = "^/private/";
    private static final String SUPER_SECRET_TOKEN = "e0PT0s5A-xDN{2-8Ro{#KzHWQ@(,,zml_PwG$6`pa\"6$2OF,ID|.9Kiy~i#jNbl(inOxhgJ++>iWYs8u@mm%C0nM0\\N&4+z\"JlGS{$b+S'L!>4q;\\.F<v)\\\"vNd[nmcW";
    private static final String RESET_REQUEST_SENT = "Reset request sent";
    private static final String AUTHORIZATION = "Authorization";

    //    Pattern publicPattern = Pattern.compile(PUBLIC_ENDPOINT_PATTERN);
    Pattern privatePattern = Pattern.compile(PRIVATE_ENDPOINT_PATTERN);
    Pattern jwtBearerAuthPattern = Pattern.compile(JWT_BEARER_AUTHORIZATION);

    @Value("${aws_ses_access_key}")
    private String AWS_SES_KEY;
    @Value("${aws_ses_secret_key}")
    private String AWS_SES_SECRET;
    @Value("${email.from}")
    private String EMAIL_FROM;
    @Value("${verification_subject}")
    private String VERIFICATION_SUBJECT;
    @Value("${verification_url}")
    private String VERIFICATION_URL;
    @Value("${label.losing.numbers}")
    private String LOSING_NUMBERS_LABEL;

    private QueueDeserializer queueDeserializer;

    private Gson GSON;

    private DrawRepository drawRepo;
    private QueueRepository queueRepo;
    private GameRepository gameRepo;
    private UserRepository userRepo;
    private UserLoginsRepository userLoginsRepo;
    private UserTypeRepository userTypeRepo;
    private UserTypeAssociationRepository userTypeAssociationRepo;
    private TokenVerificationRepository tokenVerificationRepo;
    private UserFeedbackRepository userFeedbackRepo;
    private UserEscalationRepository userEscalationRepo;

    private NumbersProvidedValidation numbersProvidedValidation = new NumbersProvidedValidation();
    private MultiplierProvidedValidation multiplierProvidedValidation = new MultiplierProvidedValidation();
    private GameNameProvided gameNameProvided = new GameNameProvided();
    private ParseUserJwtToken parseUserJwtToken;


    @Autowired
    public Api(QueueDeserializer queueDeserializer,
               DrawRepository drawRepo,
               QueueRepository queueRepo,
               GameRepository gameRepo,
               UserRepository userRepo,
               UserLoginsRepository userLoginsRepo,
               TokenVerificationRepository tokenVerificationRepo,
               UserTypeRepository userTypeRepo,
               UserTypeAssociationRepository userTypeAssociationRepo,
               UserFeedbackRepository userFeedbackRepo,
               UserEscalationRepository userEscalationRepo,
               ParseUserJwtToken parseUserJwtToken) {
        this.drawRepo = drawRepo;
        this.queueRepo = queueRepo;
        this.gameRepo = gameRepo;
        this.userRepo = userRepo;
        this.userLoginsRepo = userLoginsRepo;
        this.tokenVerificationRepo = tokenVerificationRepo;
        this.userTypeRepo = userTypeRepo;
        this.userTypeAssociationRepo = userTypeAssociationRepo;
        this.queueDeserializer = queueDeserializer;
        this.userFeedbackRepo = userFeedbackRepo;
        this.userEscalationRepo = userEscalationRepo;
        this.parseUserJwtToken = parseUserJwtToken;

        this.GSON = new GsonBuilder()
                .registerTypeAdapter(Queue.class, this.queueDeserializer)
                .registerTypeAdapterFactory(new GsonJava8TypeAdapterFactory())
                .create();

        // Filter before each request
        before((req, res) -> {
            String asJson;
            Matcher isPrivatePath = privatePattern.matcher(req.pathInfo());
            boolean hasJwtToken = false;
            if (req.headers(AUTHORIZATION) != null) {
                String token = req.headers(AUTHORIZATION);
                Matcher jwtToken = jwtBearerAuthPattern.matcher(token);
                hasJwtToken = jwtToken.find();

                GetUserFromToken userFromToken = new GetUserFromToken(
                        this.userRepo,
                        this.parseUserJwtToken,
                        token
                );

                if (!userFromToken.exists()) {
                    halt(401, "User from token does not exist");
                }

                try {
                    // now verify that the token has not expired
                    String unpacked = Jwts.parser()
                            .setSigningKey(SUPER_SECRET_TOKEN.getBytes())
                            .parseClaimsJws(jwtToken.group(1))
                            .getBody()
                            .getSubject();

                } catch (Exception e) {
                    // Lets ensure the logins table only has active sessions
                    List<UserLogins> userLogins = this.userLoginsRepo.findByJwtToken(jwtToken.group(1));
                    for(UserLogins u : userLogins) {
                        this.userLoginsRepo.delete(u.getId());
                    }
                    asJson = GSON.toJson(new SimpleResponse("Provided token not valid"));
                    halt(401, asJson);
                }
            }

            if (isPrivatePath.find() && !hasJwtToken) {
                asJson = GSON.toJson(new SimpleResponse("Not authenticated"));
                halt(401, asJson);
            }
        });

        // Filter after each request
//        after((req, res) -> log.info("Running after filter"));


        post("/private/feedback", (req, res) -> {
            FeedbackContext input;
            input = this.GSON.fromJson(req.body(), FeedbackContext.class);

            if (input == null || BLANK.equals(input.contents)) {
                res.status(400);    // Bad data was provided
                return "Required fields missing.";
            }

            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            try {
                this.userFeedbackRepo.save(new UserFeedback(input.contents, DateUtils.now(), userFromToken.user().getId()));
            } catch (Exception e) {
                res.status(404);
                return "Problem saving feedback";
            }

            res.status(200);
            return "Thank you!";
        });

        get("/private/feedback", (req, res) -> {

            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            List<UserFeedback> comments = this.userFeedbackRepo.findByUserIdAndDateReadNull(userFromToken.user().getId());

            return this.GSON.toJson(comments);
        });

        delete("/private/feedback/:id", (req, res) -> {
            String id = req.params(":id");
            Long feedbackId;
            try {
                feedbackId = Long.parseLong(id);
            } catch (NumberFormatException e) {
                res.status(400);
                return "Invalid id provided";
            }

            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            UserFeedback feedback = this.userFeedbackRepo.findOne(feedbackId);
            if (feedback == null) {
                res.status(400);
                return "feedbackId not found";
            }

            feedback.setDateRead(DateUtils.now());
            this.userFeedbackRepo.save(feedback);

            res.status(200);
            return "soft deleted";
        });

        get("/private/user-escalations", (req, res) -> {

            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            List<UserEscalation> escalations = this.userEscalationRepo.findByStatus(ACTIVE);

            return this.GSON.toJson(escalations);
        });

        get("/private/tracking", (req, res) -> {
            String asJson = null;
            try {
                GetUserFromToken userFromToken = new GetUserFromToken(
                        this.userRepo,
                        this.parseUserJwtToken,
                        req.headers(AUTHORIZATION));

                if (!userFromToken.exists()) {
                    res.status(401);
                    return "Invalid user";
                }

                List<Queue> pending = this.queueRepo.findByPersonIdAndResultsNull(userFromToken.user().getId());
                asJson = GSON.toJson(pending);

                res.status(200);
            } catch (Exception e) {
                log.error(String.format("There was a problem: %s", e.getMessage()));
                res.status(500);
            }

            return asJson;
        });

        get("/private/history", (req, res) -> {
            String asJson = null;
            try {
                GetUserFromToken userFromToken = new GetUserFromToken(
                        this.userRepo,
                        this.parseUserJwtToken,
                        req.headers(AUTHORIZATION));

                if (!userFromToken.exists()) {
                    res.status(401);
                    return "Invalid user";
                }

                List<Queue> previousNumbers = this.queueRepo.findByPersonIdAndResultsNotNull(userFromToken.user().getId());

                asJson = GSON.toJson(previousNumbers);
                res.status(200);
            } catch (Exception e) {
                log.error(String.format("There was a problem: %s", e.getMessage()));
                res.status(500);
            }

            return asJson;
        });

        post("/public/users/register", (req, res) -> {
            String asJson = null;

            Gson gson = new GsonBuilder()
                    .excludeFieldsWithoutExposeAnnotation()
                    .create();

            NewUserRegistrationContext input;
            input = gson.fromJson(req.body(), NewUserRegistrationContext.class);

            if (input == null) {
                res.status(400);    // Bad data was provided
                return "Required fields missing.";
            }

            if (!input.agreed_terms) {
                res.status(403);
                return "User has not agreed to the terms";
            }

            User user = this.userRepo.findByEmail(input.email);

            if (user != null) {
                res.status(403);    // Forbidden to have the same email already registered
                return "This email is already registered";
            }

            if (BLANK.equals(input.password)) {
                res.status(400);
                return "Password cannot be blank.";
            }

            if (input.password.length() < PASSWORD_LENGTH) {
                res.status(400);
                return String.format("Password length must be greater than %s", PASSWORD_LENGTH);
            }

            // Now we know we have a new user
            // Pre-pending the SALT as per: https://crackstation.net/hashing-security.htm
            String generatedPasswordSalt = BCrypt.gensalt(10, new SecureRandom());
            String encryptedPassword = BCrypt.hashpw(String.format("%s%s", generatedPasswordSalt, input.password), generatedPasswordSalt);
            User newUser = new User(PENDING_VERIFICATION, input.firstname, input.lastname, input.email, input.agreed_terms, generatedPasswordSalt, encryptedPassword, DateUtils.now());
            User savedUser = this.userRepo.save(newUser);

            UserType userType = this.userTypeRepo.findByType(NORMAL_USER);
            if (userType == null) {
                res.status(500);
                return "Uh oh! We do not know the user type";
            }
            UserTypeAssociation userTypeAssociation = new UserTypeAssociation(userType.getId(), savedUser.getId(), DateUtils.now());
            this.userTypeAssociationRepo.save(userTypeAssociation);

            Date tokenExpires = DateUtils.nowPlusDays(EMAIL_VERIFICATION_EXPIRY_3_DAYS);

            boolean isTokenInUse = true;
            String generatedToken = null;
            List<TokenVerification> tv = Lists.newArrayList();

            // Find a token that has not been used already
            while (isTokenInUse) {
                generatedToken = BCrypt.gensalt(10, new SecureRandom());
                generatedToken = Base64.getEncoder().encodeToString(generatedToken.getBytes("UTF-8"));
                tv = this.tokenVerificationRepo.findByTokenAndStatus(generatedToken, PENDING);
                if (tv == null || tv.size() == 0) {
                    isTokenInUse = false;
                }
            }

            TokenVerification tokenVerification = new TokenVerification(generatedToken, EMAIL_TYPE, savedUser.getId(), PENDING, DateUtils.now(), tokenExpires);
            this.tokenVerificationRepo.save(tokenVerification);

            // TODO Send email verification to user
            String verificationLink = String.format("%s/%s", VERIFICATION_URL, tokenVerification.getToken());
            EmailFormattedMessage formattedMessage = new EmailFormattedMessage(verificationLink);

            EmailNotification emailNotification = new EmailNotification(
                    AWS_SES_KEY,
                    AWS_SES_SECRET,
                    EMAIL_FROM,
                    VERIFICATION_SUBJECT,
                    formattedMessage,
                    Collections.singletonList(savedUser.getEmail()));

            try {
                emailNotification.send();
            } catch (Exception e) {
                log.error(String.format("There was a problem when sending the verification email to the user %s\nError: %s", savedUser.getEmail(), e.getMessage()));
            }

            asJson = gson.toJson(savedUser);

            return asJson;
        });

        post("/public/users/login", (req, res) -> {
            String asJson = null;

            UserLoginContext input;
            input = GSON.fromJson(req.body(), UserLoginContext.class);

            if (input == null ||
                    BLANK.equals(input.email) ||
                    BLANK.equals(input.password) ||
                    input.email == null ||
                    input.password == null) {
                res.status(400);    // Bad data was provided
                return "Required fields missing.";
            }

            User user = this.userRepo.findByEmail(input.email);
            if (user == null) {
                res.status(400);
                return "User not found";
            }

            // Pre-pending SALT as per: https://crackstation.net/hashing-security.htm
            // TODO Track how long password checks take on average, then wait a delta if we went too fast.
            // DO that because some people are clever to use duration to determine how close they are to cracking a password:
            // https://crackstation.net/hashing-security.htm
            String passwordSalt = user.getPasswordSalt();
            String encryptPassword = BCrypt.hashpw(String.format("%s%s", passwordSalt, input.password), passwordSalt);
            if (!user.getEncryptedPassword().equals(encryptPassword)) {
                // TODO Shall we throttle the number of failed attempts?
                res.status(401);
                return "Invalid credentials";
            }

            if (PENDING_VERIFICATION.equals(user.getStatus())) {
                res.status(403);
                return "Please verify your account by clicking on the link in your email.";
            }

            if (TERMINATED.equals(user.getStatus()) || CLOSED.equals(user.getStatus())) {
                res.status(401);
                return "Your account is no longer active. Please contact support.";
            }

            if (RESET_PASSWORD_FLAG.equals(user.getStatus())) {
                user.setStatus(VERIFIED);
            }

            // TODO How to handle if user has an active logged in session?

            UserTypeAssociation userTypeAssociation = this.userTypeAssociationRepo.findByUserId(user.getId());
            if (userTypeAssociation == null) {
                res.status(500);
                return "Uh oh! The user does not have a type associated.";
            }
            UserType userType = this.userTypeRepo.findById(userTypeAssociation.getUserTypeId());

            // TODO Figure out how to use this properly to encode attributes within the JWT token
            Date expirationDate = DateUtils.nowPlusDays(LOGIN_EXPIRY_JWT_1_DAY);

            Date userLoggedInTime = DateUtils.now();

            // Some content that may be useful to the client
            JwtSubjectContent jwtSubjectContent = new JwtSubjectContent(
                    user.getId(),
                    user.getEmail(),
                    userType.getType(),
                    userLoggedInTime);
            String subjectAsJson = GSON.toJson(jwtSubjectContent);

            String token = Jwts.builder()
                    .setSubject(subjectAsJson)
                    .setExpiration(expirationDate)
                    .signWith(SignatureAlgorithm.HS512, SUPER_SECRET_TOKEN.getBytes())
                    .compact();

            UserLogins userLogins = new UserLogins(user.getId(), userLoggedInTime, expirationDate, ACTIVE, token);
            this.userLoginsRepo.save(userLogins);
            // TODO Should we cache this in Redis also?

            LoginResponse loginResponse = new LoginResponse(user.getFirstName(), user.getLastName(), token);

            asJson = GSON.toJson(loginResponse);

            return asJson;
        });

        post("/private/users/logout", (req, res) -> {
            UserLogoutContext input;
            input = GSON.fromJson(req.body(), UserLogoutContext.class);

            if (input == null || BLANK.equals(input.token)) {
                res.status(400);    // Bad data was provided
                return "Required fields missing.";
            }

            List<UserLogins> userLogins = this.userLoginsRepo.findByJwtToken(input.token);
            if (userLogins != null) {
                for (UserLogins ul : userLogins) {
                    ul.logOffNow();
                    this.userLoginsRepo.save(ul);
                    // TODO Should this expire Redis cache which holds user logins?
                }
            }

            // TODO Notify website admins when we find a valid JWT token by account is not active

            res.status(200);
            return "Logged out";
        });

        // TODO Should this end point be throttled to prevent malicious attacks?
        get("/public/verify/email/:id", (req, res) -> {
            TokenVerificationContext input = new TokenVerificationContext(req.params(":id"));

            List<TokenVerification> tokenVerifications = this.tokenVerificationRepo.findByTokenAndStatus(input.token, PENDING);

            if (tokenVerifications == null || tokenVerifications.size() == 0) {
                res.status(401);
                return "Invalid verification token";
            }

            // TODO What shall we do here if there are multiple hits ?
            // Shall we alert admins?
            // Should we have a max number of verifications? Say 3 ?
            TokenVerification tv = tokenVerifications.get(0);
            // TODO Find the associated User, only set to ACTIVE if user status is "pending_verification"

            tv.tokenVerified();

            User user = this.userRepo.findOne(tv.getUserId());

            if (!PENDING_VERIFICATION.equals(user.getStatus())) {
                res.status(400);
                return "User is not pending verification.";
            }

            user.setStatus(VERIFIED);
            this.userRepo.save(user);
            tv.tokenVerified();
            this.tokenVerificationRepo.save(tv);

            return VERIFIED;
        });

        put("/private/user", (req, res) -> {
            UpdateUserContext input;
            input = GSON.fromJson(req.body(), UpdateUserContext.class);

            if (input == null) {
                res.status(400);
                return "Invalid input";
            }

            if (BLANK.equals(input.userName)) {
                res.status(400);
                return "Email cannot be blank";
            }


            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            User user = userFromToken.user();

            user.setEmail(input.userName);
            user.setFirstName(input.firstname);
            user.setLastName(input.lastname);

            if (!"".equals(input.password) && input.password != null) {
                String generatedPasswordSalt = BCrypt.gensalt(10, new SecureRandom());
                String encryptedPassword = BCrypt.hashpw(String.format("%s%s", generatedPasswordSalt, input.password), generatedPasswordSalt);
                user.setPasswordSalt(generatedPasswordSalt);
                user.setEncryptedPassword(encryptedPassword);
            }

            User saved = this.userRepo.save(user);

            return GSON.toJson(saved);
        });

        // TODO Create end point to reset password
        // This is when they are not logged in
        // send them a new one
        post("/public/users/loggedout/resetpassword", (req, res) -> {
            LoggedOutResetPasswordContext input;
            input = GSON.fromJson(req.body(), LoggedOutResetPasswordContext.class);

            if ((input == null) || BLANK.equals(input.email)) {
                res.status(200);    // intentional to throw off bad guys
                return RESET_REQUEST_SENT;
            }

            User user = this.userRepo.findByEmail(input.email);
            if (user == null) {
                // Someone gave an email we do not know about
                res.status(200);    // intentional to throw off bad guys
                return RESET_REQUEST_SENT;
            }

            RandomString random = new RandomString(10);
            String randomPassword = random.nextString();
            String generatedPasswordSalt = BCrypt.gensalt(10, new SecureRandom());
            String encryptedPassword = BCrypt.hashpw(String.format("%s%s", generatedPasswordSalt, randomPassword), generatedPasswordSalt);
            user.setStatus(RESET_PASSWORD_FLAG);
            user.setPasswordSalt(generatedPasswordSalt);
            user.setEncryptedPassword(encryptedPassword);
            this.userRepo.save(user);

            String message = String.format("Your password has been reset to: %s", randomPassword);
            EmailFormattedMessage formattedMessage = new EmailFormattedMessage(message);

            // TODO Email the user the new password and force them to change it upon login
            EmailNotification emailNotification = new EmailNotification(
                    AWS_SES_KEY,
                    AWS_SES_SECRET,
                    EMAIL_FROM,
                    "LottoCanary - Password Reset",
                    formattedMessage,
                    Collections.singletonList(user.getEmail()));

            emailNotification.send();

            res.status(200);
            return RESET_REQUEST_SENT;
        });

        delete("/private/number/:id", (req, res) -> {
            String asJson = "";
            String itemIdToDelete = req.params(":id");
            Long itemId;
            try {
                itemId = Long.parseLong(itemIdToDelete);
            } catch (NumberFormatException e) {
                res.status(400);
                return "Invalid id provided";
            }

            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                asJson = "Unknown user";
            } else {
                Queue userNumber = this.queueRepo.findOne(itemId);
                User user = userFromToken.user();
                if (userNumber.getPersonId().longValue() == user.getId()) {
                    this.queueRepo.delete(itemId);
                    res.status(200);
                    asJson = "deleted";
                } else {
                    res.status(401);
                    asJson = "Does not belong to user";
                }
            }

            return asJson;
        });

        post("/private/escalate", (req, res) -> {
            EscalateToAdminsContext input;
            input = GSON.fromJson(req.body(), EscalateToAdminsContext.class);

            if (input == null || input.message == null || BLANK.equals(input.message)) {
                res.status(400);
                return "Invalid input";
            }

            // TODO Should this be restricted to logged in users?
            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    req.headers(AUTHORIZATION));

            if (!userFromToken.exists()) {
                res.status(401);
                return "Invalid user";
            }

            User user = userFromToken.user();

            UserEscalation escalation = new UserEscalation(
                    DateUtils.now(),
                    input.message,
                    user.getEmail(),
                    ACTIVE,
                    PENDING);

            this.userEscalationRepo.save(escalation);

            res.status(200);
            return "escalated";
        });
    }
}
