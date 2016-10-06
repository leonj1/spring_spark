package com.jose.sandbox.controllers.routes;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.jose.sandbox.constants.SuperSecretToken;
import com.jose.sandbox.contexts.NewNumberPostRequestContext;
import com.jose.sandbox.model.Draw;
import com.jose.sandbox.model.Game;
import com.jose.sandbox.model.GetLottoNumberOfMatches;
import com.jose.sandbox.model.GetLottoWinningAmount;
import com.jose.sandbox.model.GetUserFromToken;
import com.jose.sandbox.model.LottoChecker;
import com.jose.sandbox.model.LottoResult;
import com.jose.sandbox.model.LottoStrategy;
import com.jose.sandbox.model.Numbers;
import com.jose.sandbox.model.ParseUserJwtToken;
import com.jose.sandbox.model.Queue;
import com.jose.sandbox.model.SimpleResponse;
import com.jose.sandbox.repository.DrawRepository;
import com.jose.sandbox.repository.GameRepository;
import com.jose.sandbox.repository.QueueRepository;
import com.jose.sandbox.repository.UserRepository;
import com.jose.sandbox.validators.numbers.CreateNumbersValidationConductor;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import spark.Request;
import spark.Response;
import spark.Route;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

@Component
public class CheckNumbersRoute implements Route {

    @Autowired @NonNull UserRepository userRepo;
    @Autowired @NonNull GameRepository gameRepo;
    @Autowired @NonNull DrawRepository drawRepo;
    @Autowired @NonNull QueueRepository queueRepo;
    @Autowired @NonNull SuperSecretToken superSecretToken;
    @Autowired @NonNull CreateNumbersValidationConductor createNumbersValidationConductor;
    @Autowired @NonNull ParseUserJwtToken parseUserJwtToken;

    @Value("${label.losing.numbers}")
    private String LOSING_NUMBERS_LABEL;

    Gson gson = new Gson();

    public String execute(Response res, String payload, String token) {
        String asJson = null;

        try {
            GetUserFromToken userFromToken = new GetUserFromToken(
                    this.userRepo,
                    this.parseUserJwtToken,
                    token
            );

            NewNumberPostRequestContext context;
            context = this.gson.fromJson(payload, NewNumberPostRequestContext.class);

            // validations
            if (!this.createNumbersValidationConductor.isSatisfied(context)) {
                res.status(this.createNumbersValidationConductor.getWorseStatus());
                return this.gson.toJson(this.createNumbersValidationConductor.failedValidations());
            }

            String requestedGame = context.game;
            if ("Mega Millions".equals(requestedGame)) {
                requestedGame = "mega";
            }

            Game game = this.gameRepo.findByName(requestedGame);

            Integer playerMultiplier = Integer.parseInt(context.multiplier);

            String pastDrawingDate = context.ticket_date;

            Queue toBeChecked = new Queue();
            toBeChecked.setPlayerNumbers(context.numbers);
            toBeChecked.setMultiplier(playerMultiplier);
            toBeChecked.setGameId(game.getId());
            toBeChecked.setPersonId(userFromToken.user().getId());

            if ((pastDrawingDate != null) && (!"".equals(pastDrawingDate))) {
                // They want us to check the status of this old ticket
                DateFormat format = new SimpleDateFormat("MM/dd/yyyy", Locale.ENGLISH);
                Date parsedDate = format.parse(pastDrawingDate);

                List<Draw> draw = this.drawRepo.findByDrawDate(parsedDate);

                if (draw.size() > 0) {
                    LottoChecker checker = new LottoChecker(
                            new LottoStrategy(
                                    new GetLottoWinningAmount(
                                            new Numbers(draw.get(0), context.numbers, playerMultiplier),
                                            new GetLottoNumberOfMatches(
                                                    draw.get(0),
                                                    context.numbers
                                            ),
                                            draw.get(0),
                                            game
                                    ),
                                    new Numbers(draw.get(0), context.numbers, playerMultiplier),
                                    draw.get(0),
                                    game,
                                    LOSING_NUMBERS_LABEL
                            )
                    );

                    LottoResult sandboxResult = checker.check();
                    if (!"".equals(sandboxResult.getStatus())) {
                        toBeChecked.setResults(sandboxResult.getStatus());
                    }

                    asJson = this.gson.toJson(sandboxResult);
                }

                toBeChecked.setDrawDate(parsedDate);
            } else {
                asJson = this.gson.toJson(new SimpleResponse("saved"));
            }

            this.queueRepo.save(toBeChecked);
            res.status(200);
        } catch (JsonSyntaxException e) {
            log.error(String.format("There was some problem: %s", e.getMessage()));
            res.status(400);
        } catch (Exception e) {
            log.error(String.format("There was a problem while attempting to check sandbox number. Message: %s", e.toString()));
        }

        return asJson;
    }

    @Override
    public Object handle(Request request, Response response) throws Exception {
        return execute(response, request.body(), request.headers("Authorization"));
    }
}
