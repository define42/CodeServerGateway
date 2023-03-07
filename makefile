all:
#	docker stop codeserver 
#	docker rm codeserver
	go fmt main.go
#	go run main.go
	docker-compose build
	docker-compose up

test:
	go run test.go

goadd:
	go mod tidy

