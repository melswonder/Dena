.PHONY: all clean fclean re

all:
	docker compose up

clean:
	docker compose down

fclean:
	docker compose down --volumes --rmi local --remove-orphans
	rm -rf ./tmp

re: fclean
	docker compose up --build