# docker-nodejs
Running Node js Project using Docker


# Docker Command 

     docker system prune -a


WARNING! This will remove:
        - all stopped containers
        - all networks not used by at least one container
        - all dangling images
        - all build cache


The docker-compose up command aggregates the output of each container (essentially running docker-compose logs -f). When the command exits, all containers are stopped. Running docker-compose up -d starts the containers in the background and leaves them running.

    docker-compose up

    docker-compose down
