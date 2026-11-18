
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                echo 'AutoForge source code checked out'
            }
        }

        stage('Backend Build') {
            steps {
                dir('1_backend') {
                    sh 'chmod +x mvnw'
                    sh './mvnw clean package -DskipTests'
                }
            }
        }

        stage('Backend Tests') {
            steps {
                dir('1_backend') {
                    sh './mvnw test'
                }
            }
        }

        stage('Frontend Build') {
            steps {
                dir('4_frontend') {
                    sh 'npm ci'
                    sh 'npm run build'
                }
            }
        }
    }

    post {
        success {
            echo 'AutoForge CI Pipeline Successful!'
        }
        failure {
            echo 'AutoForge CI Pipeline Failed!'
        }
    }
}
